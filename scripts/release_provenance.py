from __future__ import annotations

"""Build and verify VulnFlow release provenance statements.

The deterministic in-toto statement binds the release source fingerprint,
Python distribution artifacts, runtime dependency snapshot, dependency locks,
SBOM, and canonical release manifest. A DSSE Ed25519 signing rehearsal proves
that an externally supplied release key can sign the statement and that a
verifier using a pinned public key detects payload or artifact tampering.

The default release rehearsal generates an ephemeral key only in memory. The
private key is never written to disk, and the resulting signature is explicitly
reported as an untrusted rehearsal signature rather than an external trust root.
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.database_schema import CURRENT_SCHEMA_VERSION
from app.services.integrity_proof_common import PROOF_FORMAT
from app.core.public_signing import b64encode_raw, public_key_fingerprint, verify_ed25519
from scripts.distribution_artifact_rehearsal import SOURCE_DATE_EPOCH

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MANIFEST_FORMAT = "vulnflow-release-provenance/1"
BUILDER_ID = "https://vulnflow.local/builders/release-orchestrator/v1"
REPORT_JSON = Path("reports/release_provenance_verification.json")
REPORT_TEXT = Path("reports/release_provenance_verification.txt")
REPORT_ENVELOPE = Path("reports/release_provenance_rehearsal.dsse.json")
REPORT_PUBLIC_KEY = Path("reports/release_provenance_rehearsal_public_key.txt")
DIST_STATEMENT = Path("dist/release_provenance.intoto.json")
DIST_SUMS = Path("dist/RELEASE_PROVENANCE_SHA256SUMS.txt")

_GENERATED_ROOT_FILES = {
    "SHA256SUMS.txt",
    "release_verification.txt",
    "release_verification_summary.json",
    "release_verification_summary.txt",
    "verification_summary.json",
    "verification_summary.txt",
    "test_results.txt",
    "pytest_release_groups.txt",
}
_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "reports",
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pretty_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "\\" in relative:
        raise ValueError(f"unsafe release subject path: {relative}")
    return relative


def _is_source_file(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in _EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.name in {"vulnflow.db", "vulnflow-coordination.db"}:
        return False
    if len(relative.parts) >= 2 and relative.parts[0] == "data" and relative.parts[1] in {
        "evidence", "exports", "backups", "recovery"
    }:
        return False
    if len(relative.parts) == 1 and relative.name in _GENERATED_ROOT_FILES:
        return False
    if path.name == ".coverage" or path.name.startswith(".coverage."):
        return False
    if path.suffix in {".pyc", ".pyo"} or path.name.endswith(("-wal", "-shm")):
        return False
    return path.is_file()


def source_entries(root: Path = ROOT) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not _is_source_file(path, root):
            continue
        relative = _safe_relative(path, root)
        entries.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    return entries


def source_fingerprint(root: Path = ROOT) -> str:
    return sha256_bytes(canonical_json_bytes(source_entries(root)))


def _required_artifact_paths(root: Path, version: str) -> list[Path]:
    dist = root / "dist"
    wheels = sorted(dist.glob(f"bbk_vulnflow-{version}-*.whl"))
    sdists = sorted(dist.glob(f"bbk_vulnflow-{version}.tar.gz"))
    snapshots = sorted(dist.glob(f"vulnflow_runtime_dependencies-{version}-*.tar.gz"))
    if len(wheels) != 1:
        raise FileNotFoundError(f"expected one release wheel for {version}, found {len(wheels)}")
    if len(sdists) != 1:
        raise FileNotFoundError(f"expected one release sdist for {version}, found {len(sdists)}")
    if len(snapshots) != 1:
        raise FileNotFoundError(f"expected one runtime snapshot for {version}, found {len(snapshots)}")
    required = [
        wheels[0],
        sdists[0],
        snapshots[0],
        dist / "runtime_dependency_snapshot_manifest.json",
        root / "requirements.lock",
        root / "requirements-dev.lock",
        root / "bom.cdx.json",
        root / "reports/release_manifest.json",
    ]
    missing = [path for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing release provenance subjects: " + ", ".join(map(str, missing)))
    return required


def _rfc3339_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def build_statement(root: Path = ROOT) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    fingerprint = source_fingerprint(root)
    subjects = [{
        "name": "vulnflow-source-tree",
        "digest": {"sha256": fingerprint},
    }]
    for path in _required_artifact_paths(root, version):
        subjects.append({
            "name": _safe_relative(path, root),
            "digest": {"sha256": sha256_file(path)},
        })
    subjects.sort(key=lambda item: str(item["name"]))
    python_identity = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "abi": getattr(sys.implementation, "cache_tag", ""),
        "platform": sys.platform,
        "machine": platform.machine(),
        "libc": list(platform.libc_ver()),
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://vulnflow.local/build/release/v1",
                "externalParameters": {
                    "applicationVersion": version,
                    "schemaVersion": CURRENT_SCHEMA_VERSION,
                    "proofFormat": PROOF_FORMAT,
                    "sourceDateEpoch": SOURCE_DATE_EPOCH,
                },
                "internalParameters": {
                    "manifestFormat": MANIFEST_FORMAT,
                    "python": python_identity,
                },
                "resolvedDependencies": [
                    {
                        "uri": item["name"],
                        "digest": item["digest"],
                    }
                    for item in subjects
                    if item["name"] in {
                        "requirements.lock",
                        "requirements-dev.lock",
                        "dist/runtime_dependency_snapshot_manifest.json",
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "metadata": {
                    "invocationId": f"sha256:{fingerprint}",
                    "startedOn": _rfc3339_epoch(SOURCE_DATE_EPOCH),
                    "finishedOn": _rfc3339_epoch(SOURCE_DATE_EPOCH),
                    "reproducible": True,
                },
            },
        },
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


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


def _decode_raw_key(value: str, *, label: str) -> bytes:
    text = str(value or "").strip()
    try:
        raw = base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{label} must be URL-safe base64") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must decode to 32 bytes")
    return raw


def sign_statement(statement: dict[str, Any], private_key_base64: str) -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(_decode_raw_key(private_key_base64, label="private key"))
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public = b64encode_raw(public_raw)
    payload = canonical_json_bytes(statement)
    signature = private.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": public_key_fingerprint(public),
            "sig": base64.b64encode(signature).decode("ascii"),
        }],
    }


def verify_envelope(envelope: dict[str, Any], public_key_base64: str) -> dict[str, Any]:
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("unexpected DSSE payload type")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], dict):
        raise ValueError("exactly one DSSE signature is required")
    try:
        payload = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        signature = base64.b64decode(str(signatures[0].get("sig") or ""), validate=True)
    except Exception as exc:
        raise ValueError("invalid DSSE base64 encoding") from exc
    if len(signature) != 64:
        raise ValueError("invalid Ed25519 signature length")
    public_raw = _decode_raw_key(public_key_base64, label="public key")
    expected_keyid = "sha256:" + hashlib.sha256(public_raw).hexdigest()
    if signatures[0].get("keyid") != expected_keyid:
        raise ValueError("DSSE key ID does not match the pinned public key")
    public = Ed25519PublicKey.from_public_bytes(public_raw)
    public.verify(signature, pae(PAYLOAD_TYPE, payload))
    statement = json.loads(payload.decode("utf-8"))
    if canonical_json_bytes(statement) != payload:
        raise ValueError("DSSE payload is not canonical JSON")
    return statement


def expected_subject_names(root: Path = ROOT) -> set[str]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    return {"vulnflow-source-tree"} | {_safe_relative(path, root) for path in _required_artifact_paths(root, version)}


def verify_subjects(statement: dict[str, Any], root: Path = ROOT) -> list[str]:
    issues: list[str] = []
    raw_subjects = statement.get("subject")
    if not isinstance(raw_subjects, list):
        return ["subject must be a list"]
    by_name: dict[str, dict[str, Any]] = {}
    for item in raw_subjects:
        if not isinstance(item, dict):
            issues.append("subject entry must be an object")
            continue
        name = str(item.get("name") or "")
        if name in by_name:
            issues.append(f"duplicate subject: {name}")
        by_name[name] = item
    expected = expected_subject_names(root)
    if set(by_name) != expected:
        issues.append(f"subject set mismatch: expected={sorted(expected)}, actual={sorted(by_name)}")
    for name, item in by_name.items():
        digest = str((item.get("digest") or {}).get("sha256") or "")
        if name == "vulnflow-source-tree":
            actual = source_fingerprint(root)
        else:
            path = root / name
            if not path.is_file():
                issues.append(f"subject missing: {name}")
                continue
            actual = sha256_file(path)
        if digest != actual:
            issues.append(f"subject digest mismatch: {name}")
    return issues


def _statement_checks(statement: dict[str, Any], root: Path) -> list[tuple[str, bool]]:
    subjects = statement.get("subject") if isinstance(statement.get("subject"), list) else []
    names = [str(item.get("name") or "") for item in subjects if isinstance(item, dict)]
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    definition = predicate.get("buildDefinition") if isinstance(predicate.get("buildDefinition"), dict) else {}
    external = definition.get("externalParameters") if isinstance(definition.get("externalParameters"), dict) else {}
    run_details = predicate.get("runDetails") if isinstance(predicate.get("runDetails"), dict) else {}
    metadata = run_details.get("metadata") if isinstance(run_details.get("metadata"), dict) else {}
    builder = run_details.get("builder") if isinstance(run_details.get("builder"), dict) else {}
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    return [
        ("statement type", statement.get("_type") == STATEMENT_TYPE),
        ("predicate type", statement.get("predicateType") == PREDICATE_TYPE),
        ("subject count", len(subjects) == len(expected_subject_names(root))),
        ("unique subjects", len(names) == len(set(names))),
        ("source tree subject", "vulnflow-source-tree" in names),
        ("wheel subject", any(name.endswith(".whl") for name in names)),
        ("sdist subject", any(name.endswith(f"{version}.tar.gz") for name in names)),
        ("runtime snapshot subject", any("runtime_dependencies" in name for name in names)),
        ("runtime lock subject", "requirements.lock" in names),
        ("development lock subject", "requirements-dev.lock" in names),
        ("SBOM subject", "bom.cdx.json" in names),
        ("release manifest subject", "reports/release_manifest.json" in names),
        ("all subject hashes current", not verify_subjects(statement, root)),
        ("source fingerprint", any(item.get("name") == "vulnflow-source-tree" and (item.get("digest") or {}).get("sha256") == source_fingerprint(root) for item in subjects if isinstance(item, dict))),
        ("application version", external.get("applicationVersion") == version),
        ("schema version", external.get("schemaVersion") == CURRENT_SCHEMA_VERSION),
        ("proof format", external.get("proofFormat") == PROOF_FORMAT),
        ("source date epoch", external.get("sourceDateEpoch") == SOURCE_DATE_EPOCH),
        ("builder identity", builder.get("id") == BUILDER_ID),
        ("invocation identity", metadata.get("invocationId") == f"sha256:{source_fingerprint(root)}"),
    ]


def write_statement(root: Path, statement: dict[str, Any]) -> None:
    path = root / DIST_STATEMENT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pretty_json(statement), encoding="utf-8")
    sums = root / DIST_SUMS
    sums.write_text(f"{sha256_file(path)}  {path.name}\n", encoding="utf-8")


def run_rehearsal(root: Path = ROOT) -> dict[str, Any]:
    statement = build_statement(root)
    write_statement(root, statement)
    private_key, public_key = keypair()
    envelope = sign_statement(statement, private_key)
    verified = verify_envelope(envelope, public_key)

    wrong_private, wrong_public = keypair()
    del wrong_private
    wrong_key_rejected = False
    try:
        verify_envelope(envelope, wrong_public)
    except Exception:
        wrong_key_rejected = True

    tampered = json.loads(json.dumps(envelope))
    payload = bytearray(base64.b64decode(tampered["payload"]))
    payload[-1] ^= 1
    tampered["payload"] = base64.b64encode(payload).decode("ascii")
    tampered_rejected = False
    try:
        verify_envelope(tampered, public_key)
    except Exception:
        tampered_rejected = True

    checks = _statement_checks(statement, root)
    checks.extend([
        ("pinned public key signature", verified == statement),
        ("wrong public key rejected", wrong_key_rejected),
        ("tampered payload rejected", tampered_rejected),
        ("private key not serialized", private_key not in pretty_json(envelope) and private_key not in pretty_json(statement)),
    ])
    passed = sum(1 for _, ok in checks if ok)
    report = {
        "format": MANIFEST_FORMAT,
        "application_version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "trust_state": "rehearsal-key-untrusted",
        "notice": "The rehearsal key is generated in memory for release verification and is not an externally pinned production trust root.",
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "checks": [{"name": name, "passed": ok} for name, ok in checks],
        "statement_sha256": sha256_bytes(canonical_json_bytes(statement)),
        "source_fingerprint_sha256": source_fingerprint(root),
        "subject_count": len(statement["subject"]),
        "rehearsal_public_key_base64": public_key,
        "rehearsal_public_key_fingerprint": public_key_fingerprint(public_key),
        "private_key_persisted": False,
    }
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (root / REPORT_JSON).write_text(pretty_json(report), encoding="utf-8")
    (root / REPORT_ENVELOPE).write_text(pretty_json(envelope), encoding="utf-8")
    (root / REPORT_PUBLIC_KEY).write_text(public_key + "\n", encoding="utf-8")
    lines = [
        f"VulnFlow {report['application_version']} signed release provenance rehearsal",
        "",
        f"trust_state: {report['trust_state']}",
        f"checks: {passed}/{len(checks)}",
        f"subjects: {report['subject_count']}",
        f"statement_sha256: {report['statement_sha256']}",
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
        raise RuntimeError("release provenance rehearsal failed: " + ", ".join(failed))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and verify VulnFlow release provenance.")
    parser.add_argument("--sign-private-key-base64", default="", help="Sign the current statement with an external raw Ed25519 private key seed.")
    parser.add_argument("--envelope-output", default="dist/release_provenance.dsse.json")
    parser.add_argument("--verify-envelope", default="")
    parser.add_argument("--public-key-base64", default="")
    args = parser.parse_args()

    if args.verify_envelope:
        if not args.public_key_base64:
            raise SystemExit("--public-key-base64 is required with --verify-envelope")
        envelope = json.loads((ROOT / args.verify_envelope).read_text(encoding="utf-8"))
        statement = verify_envelope(envelope, args.public_key_base64)
        issues = verify_subjects(statement, ROOT)
        if issues:
            raise SystemExit("release provenance verification failed:\n- " + "\n- ".join(issues))
        print("release provenance signature and subjects verified")
        return

    if args.sign_private_key_base64:
        statement = build_statement(ROOT)
        write_statement(ROOT, statement)
        envelope = sign_statement(statement, args.sign_private_key_base64)
        output = ROOT / args.envelope_output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(pretty_json(envelope), encoding="utf-8")
        print(output)
        return

    report = run_rehearsal(ROOT)
    print(f"release provenance rehearsal: {report['checks_passed']}/{report['checks_total']} passed")


if __name__ == "__main__":
    main()
