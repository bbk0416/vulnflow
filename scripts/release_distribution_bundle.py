from __future__ import annotations

"""Build deterministic VulnFlow project archives and signed release kits."""

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.database_schema import CURRENT_SCHEMA_VERSION
from app.services.integrity_proof_common import PROOF_FORMAT
from app.core.public_signing import b64encode_raw, public_key_fingerprint
from scripts.distribution_artifact_rehearsal import SOURCE_DATE_EPOCH
from scripts.release_provenance import canonical_json_bytes, sha256_file, source_fingerprint
from scripts.verify_release_distribution import (
    INDEX_FORMAT,
    PAYLOAD_TYPE,
    REQUIRED_ROLES,
    verify_directory,
    verify_envelope,
)

REPORT_JSON = Path("reports/release_distribution_bundle_verification.json")
REPORT_TEXT = Path("reports/release_distribution_bundle_verification.txt")
DOC_PATH = Path("docs/90_SIGNED_RELEASE_DISTRIBUTION_BUNDLE.md")
FORBIDDEN_PARTS = {
    ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "__pycache__", "build"
}
FORBIDDEN_NAMES = {".release_verification_journal.json"}
RUNTIME_SUFFIXES = ("-wal", "-shm")


def pretty_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp_tuple(epoch: int = SOURCE_DATE_EPOCH) -> tuple[int, int, int, int, int, int]:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second - dt.second % 2)


def _safe_relative(path: Path, root: Path) -> str:
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "\\" in relative:
        raise ValueError(f"unsafe package path: {relative}")
    return relative


def _include_package_file(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if path.is_symlink() or not path.is_file():
        return False
    if path.name == "SHA256SUMS.txt" or path.name in FORBIDDEN_NAMES:
        return False
    if any(part in FORBIDDEN_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.suffix in {".pyc", ".pyo", ".sqlite3", ".db"} or path.name.endswith(RUNTIME_SUFFIXES):
        return False
    return True


def package_entries(root: Path) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    for path in sorted(root.rglob("*")):
        if not _include_package_file(path, root):
            continue
        entries.append((_safe_relative(path, root), path.read_bytes()))
    if not entries:
        raise ValueError("project package contains no files")
    return entries


def internal_manifest_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    lines = [f"{sha256_bytes(data)}  {name}" for name, data in entries]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _zip_info(name: str, *, directory: bool, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_timestamp_tuple())
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | (0o755 if executable else 0o644))
    info.external_attr = mode << 16
    if directory:
        info.external_attr |= 0x10
    return info


def _write_deterministic_zip(output: Path, root_name: str, entries: list[tuple[str, bytes]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    root_name = root_name.rstrip("/")
    directories = {root_name + "/"}
    for name, _ in entries:
        parts = PurePosixPath(name).parts[:-1]
        current = root_name
        for part in parts:
            current += "/" + part
            directories.add(current + "/")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for directory in sorted(directories):
            archive.writestr(_zip_info(directory, directory=True), b"")
        for name, data in sorted(entries):
            archive_name = f"{root_name}/{name}"
            executable = name.endswith(".sh")
            archive.writestr(_zip_info(archive_name, directory=False, executable=executable), data)


def build_project_archive(root: Path, output: Path) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    entries = package_entries(root)
    manifest = internal_manifest_bytes(entries)
    archive_entries = entries + [("SHA256SUMS.txt", manifest)]
    _write_deterministic_zip(output, f"VulnFlow-{version}", archive_entries)
    result = verify_project_archive(output, version=version)
    result["sha256"] = sha256_file(output)
    result["size"] = output.stat().st_size
    return result


def _parse_manifest(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in data.decode("utf-8").splitlines():
        if not raw_line:
            continue
        if len(raw_line) < 67 or raw_line[64:66] != "  ":
            raise ValueError("invalid internal SHA256SUMS line")
        digest, name = raw_line[:64], raw_line[66:]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("invalid internal SHA-256 digest")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name or name in result:
            raise ValueError(f"unsafe or duplicate internal manifest path: {name}")
        result[name] = digest
    return result


def verify_project_archive(path: Path, *, version: str) -> dict[str, Any]:
    expected_root = f"VulnFlow-{version}"
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP entry")
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                raise ValueError(f"unsafe ZIP entry: {name}")
            if not name.startswith(expected_root + "/"):
                raise ValueError(f"unexpected ZIP root: {name}")
        expected_timestamp = _timestamp_tuple()
        if any(info.date_time != expected_timestamp for info in infos):
            raise ValueError("non-deterministic ZIP timestamp")
        manifest_name = f"{expected_root}/SHA256SUMS.txt"
        manifest = _parse_manifest(archive.read(manifest_name))
        actual_files = {
            name[len(expected_root) + 1:]
            for name in names
            if not name.endswith("/") and name != manifest_name
        }
        if set(manifest) != actual_files:
            raise ValueError("internal manifest file set mismatch")
        for relative, expected in manifest.items():
            actual = sha256_bytes(archive.read(f"{expected_root}/{relative}"))
            if actual != expected:
                raise ValueError(f"internal project archive digest mismatch: {relative}")
        bad = [name for name in actual_files if any(part in FORBIDDEN_PARTS for part in PurePosixPath(name).parts)]
        if bad:
            raise ValueError("forbidden files in project archive: " + ", ".join(bad[:5]))
        return {
            "root": expected_root,
            "files": len(actual_files) + 1,
            "manifest_entries": len(manifest),
            "zip_entries": len(infos),
            "timestamps_normalized": True,
        }


def _decode_private_key(value: str) -> bytes:
    text = str(value or "").strip()
    raw = base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    if len(raw) != 32:
        raise ValueError("private key must decode to 32 bytes")
    return raw


def keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode_raw(private_raw), b64encode_raw(public_raw)


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


def sign_index(index: dict[str, Any], private_key_base64: str) -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(_decode_private_key(private_key_base64))
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public = b64encode_raw(public_raw)
    payload = canonical_json_bytes(index)
    signature = private.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": public_key_fingerprint(public),
            "sig": base64.b64encode(signature).decode("ascii"),
        }],
    }


def _artifact_definitions(root: Path, project_archive: Path) -> list[tuple[str, Path, str]]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    vtag = version.replace(".", "_")
    dist = root / "dist"
    wheel = sorted(dist.glob(f"bbk_vulnflow-{version}-*.whl"))
    sdist = sorted(dist.glob(f"bbk_vulnflow-{version}.tar.gz"))
    snapshot = sorted(dist.glob(f"vulnflow_runtime_dependencies-{version}-*.tar.gz"))
    if len(wheel) != 1 or len(sdist) != 1 or len(snapshot) != 1:
        raise FileNotFoundError("release wheel, sdist, or runtime snapshot is missing")
    return [
        ("project_archive", project_archive, project_archive.name),
        ("python_wheel", wheel[0], wheel[0].name),
        ("source_distribution", sdist[0], sdist[0].name),
        ("runtime_dependency_snapshot", snapshot[0], snapshot[0].name),
        ("runtime_snapshot_manifest", dist / "runtime_dependency_snapshot_manifest.json", f"BBK_VULNFLOW_PROJECT_V{vtag}_RUNTIME_SNAPSHOT_MANIFEST.json"),
        ("release_provenance_statement", dist / "release_provenance.intoto.json", f"BBK_VULNFLOW_PROJECT_V{vtag}_RELEASE_PROVENANCE.intoto.json"),
        ("release_manifest", root / "reports/release_manifest.json", f"BBK_VULNFLOW_PROJECT_V{vtag}_RELEASE_MANIFEST.json"),
        ("cyclonedx_sbom", root / "bom.cdx.json", f"BBK_VULNFLOW_PROJECT_V{vtag}_SBOM.cdx.json"),
        ("verification_summary", root / "verification_summary.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_VERIFICATION.txt"),
        ("architecture_verification", root / "reports/architecture_review.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_ARCHITECTURE_VERIFY.txt"),
        ("runtime_soak_verification", root / "reports/runtime_stability_soak_verification.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_SOAK_VERIFICATION.txt"),
        ("container_deployment_verification", root / "reports/container_deployment_rehearsal_verification.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_CONTAINER_DEPLOYMENT_REHEARSAL.txt"),
        ("distribution_artifact_verification", root / "reports/distribution_artifact_rehearsal_verification.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_DISTRIBUTION_ARTIFACT_REHEARSAL.txt"),
        ("runtime_snapshot_verification", root / "reports/runtime_dependency_snapshot_verification.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_RUNTIME_DEPENDENCY_SNAPSHOT.txt"),
        ("release_provenance_verification", root / "reports/release_provenance_verification.txt", f"BBK_VULNFLOW_PROJECT_V{vtag}_RELEASE_PROVENANCE_VERIFICATION.txt"),
        ("offline_deployment_activation", root / "scripts/offline_deployment_activation.py", "offline_deployment_activation.py"),
        ("offline_deployment_keyring", root / "scripts/offline_deployment_keyring.py", "offline_deployment_keyring.py"),
        ("offline_deployment_audit", root / "scripts/offline_deployment_audit.py", "offline_deployment_audit.py"),
        ("offline_deployment_witness", root / "scripts/offline_deployment_witness.py", "offline_deployment_witness.py"),
        ("offline_deployment_recovery", root / "scripts/offline_deployment_recovery.py", "offline_deployment_recovery.py"),
        ("offline_deployment_preflight", root / "scripts/offline_deployment_preflight.py", "offline_deployment_preflight.py"),
        ("offline_deployment_history", root / "scripts/offline_deployment_history.py", "offline_deployment_history.py"),
        ("offline_deployment_bootstrap", root / "scripts/offline_deployment_bootstrap.py", "offline_deployment_bootstrap.py"),
        ("offline_deployment_manager", root / "scripts/manage_offline_deployments.py", "manage_offline_deployments.py"),
    ]


def stage_artifacts(root: Path, project_archive: Path, staging: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    roles: set[str] = set()
    filenames: set[str] = set()
    staging.mkdir(parents=True, exist_ok=True)
    for role, source, filename in _artifact_definitions(root, project_archive):
        if role in roles or filename in filenames:
            raise ValueError("duplicate release artifact role or filename")
        roles.add(role)
        filenames.add(filename)
        if source.is_symlink() or not source.is_file():
            raise FileNotFoundError(f"release artifact missing: {source}")
        destination = staging / filename
        shutil.copyfile(source, destination)
        artifacts.append({
            "role": role,
            "filename": filename,
            "size": destination.stat().st_size,
            "sha256": sha256_file(destination),
        })
    artifacts.sort(key=lambda item: item["role"])
    if {item["role"] for item in artifacts} != set(REQUIRED_ROLES):
        raise ValueError("release artifact role contract mismatch")
    return artifacts


def build_index(root: Path, artifacts: list[dict[str, Any]], *, trust_state: str) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    return {
        "format": INDEX_FORMAT,
        "title": f"VulnFlow {version} signed release distribution index",
        "version": version,
        "schemaVersion": CURRENT_SCHEMA_VERSION,
        "proofFormat": PROOF_FORMAT,
        "generatedAt": datetime.fromtimestamp(SOURCE_DATE_EPOCH, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "sourceFingerprintSha256": source_fingerprint(root),
        "trustState": trust_state,
        "requiredRoles": list(REQUIRED_ROLES),
        "artifacts": artifacts,
    }


def write_distribution_metadata(
    staging: Path,
    index: dict[str, Any],
    envelope: dict[str, Any],
    public_key: str,
) -> None:
    (staging / "release_distribution_index.json").write_bytes(canonical_json_bytes(index) + b"\n")
    (staging / "release_distribution_index.dsse.json").write_text(pretty_json(envelope), encoding="utf-8")
    (staging / "release_distribution_public_key.txt").write_text(public_key + "\n", encoding="utf-8")
    shutil.copyfile(ROOT / "scripts/verify_release_distribution.py", staging / "verify_release_distribution.py")
    readme = [
        f"VulnFlow {index['version']} offline release distribution verification",
        "",
        "1. Pin release_distribution_public_key.txt through an independent channel.",
        "2. Run:",
        "   python verify_release_distribution.py --directory . --expected-version " + str(index["version"]),
        "",
        "The bundled rehearsal key is not an organizational production trust root.",
    ]
    (staging / "VERIFY_RELEASE.txt").write_text("\n".join(readme) + "\n", encoding="utf-8")
    deploy = [
        f"VulnFlow {index['version']} signed offline deployment bootstrap",
        "",
        "Before deployment, obtain both values through an independent channel:",
        "- the release-kit ZIP SHA-256",
        "- the release public-key fingerprint (sha256:<64 hex>)",
        "",
        "Run from outside the extracted kit:",
        "  python offline_deployment_bootstrap.py \\",
        "    --release-kit BBK_VULNFLOW_RELEASE_KIT.zip \\",
        "    --target ./vulnflow-deployment \\",
        "    --expected-kit-sha256 <64-hex> \\",
        "    --expected-public-key-fingerprint sha256:<64-hex> \\",
        "    --expected-version " + str(index["version"]),
        "",
        "The bootstrap creates mode-0600 initial credentials and never prints secrets in its report.",
        "",
        "After stopping the service, inspect retained deployments with:",
        "  python manage_offline_deployments.py list --target ./vulnflow-deployment",
        "Rollback and prune require explicit confirmation values; see --help.",
    ]
    (staging / "DEPLOY_OFFLINE.txt").write_text("\n".join(deploy) + "\n", encoding="utf-8")


def build_release_kit(staging: Path, output: Path, *, version: str) -> dict[str, Any]:
    entries = [(path.name, path.read_bytes()) for path in sorted(staging.iterdir()) if path.is_file()]
    _write_deterministic_zip(output, f"VulnFlow-Release-{version}", entries)
    with zipfile.ZipFile(output) as archive:
        names = [item.filename for item in archive.infolist()]
        if len(names) != len(set(names)):
            raise ValueError("duplicate release kit ZIP entry")
        if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name for name in names):
            raise ValueError("unsafe release kit ZIP path")
        if any(item.date_time != _timestamp_tuple() for item in archive.infolist()):
            raise ValueError("release kit ZIP timestamp is not normalized")
    return {"sha256": sha256_file(output), "size": output.stat().st_size, "entries": len(entries)}


def _run_standalone_verifier(staging: Path, version: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(staging / "verify_release_distribution.py"), "--directory", str(staging), "--expected-version", version],
        cwd=staging,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


def run_rehearsal(root: Path = ROOT) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    checks: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow-release-bundle-") as temp_raw:
        temp = Path(temp_raw)
        project_a = temp / f"BBK_VULNFLOW_PROJECT_V{version.replace('.', '_')}_A.zip"
        project_b = temp / f"BBK_VULNFLOW_PROJECT_V{version.replace('.', '_')}_B.zip"
        result_a = build_project_archive(root, project_a)
        result_b = build_project_archive(root, project_b)
        checks.extend([
            ("project archive repeat hash", result_a["sha256"] == result_b["sha256"]),
            ("project archive repeat size", result_a["size"] == result_b["size"]),
            ("project archive internal manifest", result_a["manifest_entries"] > 500),
            ("project archive normalized timestamps", result_a["timestamps_normalized"]),
            ("project archive expected root", result_a["root"] == f"VulnFlow-{version}"),
        ])

        staging = temp / "staging"
        artifacts = stage_artifacts(root, project_a, staging)
        private_key, public_key = keypair()
        index = build_index(root, artifacts, trust_state="rehearsal-key-untrusted")
        envelope = sign_index(index, private_key)
        write_distribution_metadata(staging, index, envelope, public_key)
        verified_index = verify_envelope(envelope, public_key)
        directory_result = verify_directory(staging, verified_index, expected_version=version)
        checks.extend([
            ("distribution index format", index["format"] == INDEX_FORMAT),
            ("distribution index version", index["version"] == version),
            ("distribution role count", len(artifacts) == len(REQUIRED_ROLES)),
            ("distribution unique roles", len({item["role"] for item in artifacts}) == len(artifacts)),
            ("distribution unique filenames", len({item["filename"] for item in artifacts}) == len(artifacts)),
            ("distribution artifact hashes", directory_result["artifacts_verified"] == len(REQUIRED_ROLES)),
            ("distribution source fingerprint", directory_result["source_fingerprint_sha256"] == source_fingerprint(root)),
            ("DSSE pinned key signature", verified_index == index),
            ("private key not serialized", private_key not in pretty_json(index) and private_key not in pretty_json(envelope)),
        ])

        wrong_private, wrong_public = keypair()
        del wrong_private
        wrong_key_rejected = False
        try:
            verify_envelope(envelope, wrong_public)
        except Exception:
            wrong_key_rejected = True
        checks.append(("wrong public key rejected", wrong_key_rejected))

        tampered_envelope = json.loads(json.dumps(envelope))
        payload = bytearray(base64.b64decode(tampered_envelope["payload"]))
        payload[-1] ^= 1
        tampered_envelope["payload"] = base64.b64encode(payload).decode("ascii")
        tampered_index_rejected = False
        try:
            verify_envelope(tampered_envelope, public_key)
        except Exception:
            tampered_index_rejected = True
        checks.append(("tampered signed index rejected", tampered_index_rejected))

        artifact_path = staging / artifacts[0]["filename"]
        original = artifact_path.read_bytes()
        artifact_path.write_bytes(original + b"tamper")
        tampered_artifact_rejected = False
        try:
            verify_directory(staging, index, expected_version=version)
        except Exception:
            tampered_artifact_rejected = True
        artifact_path.write_bytes(original)
        checks.append(("tampered artifact rejected", tampered_artifact_rejected))

        missing_path = staging / artifacts[1]["filename"]
        missing_copy = missing_path.read_bytes()
        missing_path.unlink()
        missing_artifact_rejected = False
        try:
            verify_directory(staging, index, expected_version=version)
        except Exception:
            missing_artifact_rejected = True
        missing_path.write_bytes(missing_copy)
        checks.append(("missing artifact rejected", missing_artifact_rejected))

        standalone = _run_standalone_verifier(staging, version)
        checks.extend([
            ("standalone verifier exit", standalone.returncode == 0),
            ("standalone verifier output", f"{len(REQUIRED_ROLES)} artifacts" in standalone.stdout),
        ])

        kit_a = temp / "release-kit-a.zip"
        kit_b = temp / "release-kit-b.zip"
        kit_result_a = build_release_kit(staging, kit_a, version=version)
        kit_result_b = build_release_kit(staging, kit_b, version=version)
        checks.extend([
            ("release kit repeat hash", kit_result_a["sha256"] == kit_result_b["sha256"]),
            ("release kit repeat size", kit_result_a["size"] == kit_result_b["size"]),
            ("release kit entry count", kit_result_a["entries"] == len(REQUIRED_ROLES) + 6),
        ])

        extracted = temp / "extracted"
        with zipfile.ZipFile(kit_a) as archive:
            archive.extractall(extracted)
        kit_dir = extracted / f"VulnFlow-Release-{version}"
        extracted_verify = _run_standalone_verifier(kit_dir, version)
        checks.extend([
            ("extracted release kit directory", kit_dir.is_dir()),
            ("extracted release kit verifier", extracted_verify.returncode == 0),
            ("extracted release kit artifacts", all((kit_dir / item["filename"]).is_file() for item in artifacts)),
        ])

        checks.extend([
            ("schema version", index["schemaVersion"] == CURRENT_SCHEMA_VERSION),
            ("proof format", index["proofFormat"] == PROOF_FORMAT),
            ("rehearsal trust state", index["trustState"] == "rehearsal-key-untrusted"),
            ("verifier script included", (staging / "verify_release_distribution.py").is_file()),
            ("verification instructions included", (staging / "VERIFY_RELEASE.txt").is_file()),
            ("deployment bootstrap signed", {
                "offline_deployment_activation",
                "offline_deployment_witness",
                "offline_deployment_history",
                "offline_deployment_bootstrap",
                "offline_deployment_manager",
            }.issubset({item["role"] for item in artifacts})),
            ("deployment instructions included", (staging / "DEPLOY_OFFLINE.txt").is_file()),
        ])

    passed = sum(1 for _, ok in checks if ok)
    report = {
        "format": "vulnflow-release-distribution-bundle-verification/1",
        "application_version": version,
        "trust_state": "rehearsal-key-untrusted",
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "checks": [{"name": name, "passed": ok} for name, ok in checks],
        "project_archive_sha256": result_a["sha256"],
        "release_kit_sha256": kit_result_a["sha256"],
        "artifact_count": len(REQUIRED_ROLES),
        "source_fingerprint_sha256": source_fingerprint(root),
        "rehearsal_public_key_base64": public_key,
        "rehearsal_public_key_fingerprint": public_key_fingerprint(public_key),
        "private_key_persisted": False,
        "notice": "The rehearsal key is generated in memory and is not an externally pinned organizational release trust root.",
    }
    (root / REPORT_JSON).write_text(pretty_json(report), encoding="utf-8")
    lines = [
        f"VulnFlow {version} signed release distribution bundle rehearsal",
        "",
        f"trust_state: {report['trust_state']}",
        f"checks: {passed}/{len(checks)}",
        f"artifacts: {report['artifact_count']}",
        f"project_archive_sha256: {report['project_archive_sha256']}",
        f"release_kit_sha256: {report['release_kit_sha256']}",
        f"source_fingerprint_sha256: {report['source_fingerprint_sha256']}",
        f"rehearsal_public_key_fingerprint: {report['rehearsal_public_key_fingerprint']}",
        "private_key_persisted: false",
        "",
    ]
    lines.extend(f"[{'PASS' if ok else 'FAIL'}] {name}" for name, ok in checks)
    lines.extend(["", "LIMIT: " + report["notice"]])
    (root / REPORT_TEXT).write_text("\n".join(lines) + "\n", encoding="utf-8")
    if passed != len(checks):
        failed = [name for name, ok in checks if not ok]
        raise RuntimeError("release distribution bundle rehearsal failed: " + ", ".join(failed))
    return report


def finalize_distribution(
    root: Path,
    project_archive: Path,
    output_dir: Path,
    *,
    private_key_base64: str = "",
) -> dict[str, Path]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    vtag = version.replace(".", "_")
    output_dir.mkdir(parents=True, exist_ok=True)
    staging = output_dir / f".vulnflow-release-{version}-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    artifacts = stage_artifacts(root, project_archive, staging)
    if private_key_base64:
        private_key = private_key_base64
        private = Ed25519PrivateKey.from_private_bytes(_decode_private_key(private_key))
        public_key = b64encode_raw(private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ))
        trust_state = "externally-supplied-key"
    else:
        private_key, public_key = keypair()
        trust_state = "rehearsal-key-untrusted"
    index = build_index(root, artifacts, trust_state=trust_state)
    envelope = sign_index(index, private_key)
    write_distribution_metadata(staging, index, envelope, public_key)
    verify_directory(staging, verify_envelope(envelope, public_key), expected_version=version)
    verifier = _run_standalone_verifier(staging, version)
    if verifier.returncode != 0:
        raise RuntimeError("standalone distribution verifier failed:\n" + verifier.stdout[-4000:])

    kit_name = f"BBK_VULNFLOW_RELEASE_KIT_V{vtag}_20260726.zip"
    kit_path = output_dir / kit_name
    build_release_kit(staging, kit_path, version=version)
    index_path = output_dir / f"BBK_VULNFLOW_RELEASE_INDEX_V{vtag}.json"
    envelope_path = output_dir / f"BBK_VULNFLOW_RELEASE_INDEX_V{vtag}.dsse.json"
    public_path = output_dir / f"BBK_VULNFLOW_RELEASE_INDEX_V{vtag}_PUBLIC_KEY.txt"
    verifier_path = output_dir / f"BBK_VULNFLOW_RELEASE_INDEX_V{vtag}_VERIFY.py"
    index_path.write_bytes(canonical_json_bytes(index) + b"\n")
    envelope_path.write_text(pretty_json(envelope), encoding="utf-8")
    public_path.write_text(public_key + "\n", encoding="utf-8")
    shutil.copyfile(root / "scripts/verify_release_distribution.py", verifier_path)
    sums_path = output_dir / f"BBK_VULNFLOW_RELEASE_KIT_V{vtag}_SHA256SUMS.txt"
    sums_path.write_text(
        "\n".join([
            f"{sha256_file(kit_path)}  {kit_path.name}",
            f"{sha256_file(index_path)}  {index_path.name}",
            f"{sha256_file(envelope_path)}  {envelope_path.name}",
            f"{sha256_file(public_path)}  {public_path.name}",
            f"{sha256_file(verifier_path)}  {verifier_path.name}",
        ]) + "\n",
        encoding="utf-8",
    )
    shutil.rmtree(staging)
    return {
        "kit": kit_path,
        "index": index_path,
        "envelope": envelope_path,
        "public_key": public_path,
        "verifier": verifier_path,
        "sha256sums": sums_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic VulnFlow release archives and signed distribution kits.")
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--project-archive", default="")
    parser.add_argument("--output-dir", default="/mnt/data")
    parser.add_argument("--sign-private-key-base64", default="")
    args = parser.parse_args()
    if args.finalize:
        if not args.project_archive:
            raise SystemExit("--project-archive is required with --finalize")
        outputs = finalize_distribution(
            ROOT,
            Path(args.project_archive).resolve(),
            Path(args.output_dir).resolve(),
            private_key_base64=args.sign_private_key_base64,
        )
        for name, path in outputs.items():
            print(f"{name}: {path}")
        return
    report = run_rehearsal(ROOT)
    print(f"release distribution bundle rehearsal: {report['checks_passed']}/{report['checks_total']} passed")


if __name__ == "__main__":
    main()
