from __future__ import annotations

"""Offline verifier for a VulnFlow release distribution directory.

This file intentionally depends only on Python's standard library plus
``cryptography``. It does not import the VulnFlow package or trust files from
inside the project archive. The verifier requires a separately pinned raw
Ed25519 public key and checks the DSSE signature, canonical distribution index,
required artifact roles, file sizes, SHA-256 digests, and provenance linkage.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

INDEX_FORMAT = "vulnflow-release-distribution-index/1"
PAYLOAD_TYPE = "application/vnd.vulnflow.release-distribution-index+json"
REQUIRED_ROLES = (
    "project_archive",
    "python_wheel",
    "source_distribution",
    "runtime_dependency_snapshot",
    "runtime_snapshot_manifest",
    "release_provenance_statement",
    "release_manifest",
    "cyclonedx_sbom",
    "verification_summary",
    "architecture_verification",
    "runtime_soak_verification",
    "container_deployment_verification",
    "distribution_artifact_verification",
    "runtime_snapshot_verification",
    "release_provenance_verification",
    "offline_deployment_bootstrap",
)


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_raw_public_key(value: str) -> bytes:
    text = str(value or "").strip()
    try:
        raw = base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    except Exception as exc:
        raise ValueError("public key must be URL-safe base64") from exc
    if len(raw) != 32:
        raise ValueError("public key must decode to 32 bytes")
    return raw


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


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
    public_raw = _decode_raw_public_key(public_key_base64)
    expected_keyid = "sha256:" + hashlib.sha256(public_raw).hexdigest()
    if signatures[0].get("keyid") != expected_keyid:
        raise ValueError("DSSE key ID does not match the pinned public key")
    Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _pae(PAYLOAD_TYPE, payload))
    index = json.loads(payload.decode("utf-8"))
    if canonical_json_bytes(index) != payload:
        raise ValueError("DSSE payload is not canonical JSON")
    return index


def _safe_filename(value: object) -> str:
    filename = str(value or "")
    pure = PurePosixPath(filename)
    if not filename or pure.is_absolute() or len(pure.parts) != 1 or ".." in pure.parts or "\\" in filename:
        raise ValueError(f"unsafe artifact filename: {filename!r}")
    return filename


def _provenance_subject_map(statement: dict[str, Any]) -> dict[str, str]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise ValueError("release provenance subject must be a list")
    result: dict[str, str] = {}
    for item in subjects:
        if not isinstance(item, dict):
            raise ValueError("release provenance subject entry must be an object")
        name = str(item.get("name") or "")
        digest = str((item.get("digest") or {}).get("sha256") or "")
        if not name or len(digest) != 64:
            raise ValueError("invalid release provenance subject")
        if name in result:
            raise ValueError(f"duplicate release provenance subject: {name}")
        result[name] = digest
    return result


def verify_directory(
    directory: Path,
    index: dict[str, Any],
    *,
    expected_version: str | None = None,
) -> dict[str, Any]:
    directory = directory.resolve()
    if index.get("format") != INDEX_FORMAT:
        raise ValueError("unexpected release distribution index format")
    version = str(index.get("version") or "")
    if not version:
        raise ValueError("release version is missing")
    if expected_version and version != expected_version:
        raise ValueError(f"release version mismatch: expected {expected_version}, got {version}")
    declared_roles = index.get("requiredRoles")
    if declared_roles != list(REQUIRED_ROLES):
        raise ValueError("required role contract mismatch")
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("artifacts must be a list")
    by_role: dict[str, dict[str, Any]] = {}
    filenames: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("artifact entry must be an object")
        role = str(item.get("role") or "")
        if role in by_role:
            raise ValueError(f"duplicate artifact role: {role}")
        filename = _safe_filename(item.get("filename"))
        if filename in filenames:
            raise ValueError(f"duplicate artifact filename: {filename}")
        filenames.add(filename)
        by_role[role] = item
    if set(by_role) != set(REQUIRED_ROLES):
        raise ValueError("artifact role set mismatch")

    verified: list[dict[str, Any]] = []
    for role in REQUIRED_ROLES:
        item = by_role[role]
        filename = _safe_filename(item.get("filename"))
        path = directory / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"artifact missing or not a regular file: {filename}")
        size = int(item.get("size") or -1)
        if path.stat().st_size != size:
            raise ValueError(f"artifact size mismatch: {filename}")
        expected_sha = str(item.get("sha256") or "")
        actual_sha = sha256_file(path)
        if expected_sha != actual_sha:
            raise ValueError(f"artifact digest mismatch: {filename}")
        verified.append({"role": role, "filename": filename, "sha256": actual_sha, "size": size})

    provenance_path = directory / _safe_filename(by_role["release_provenance_statement"]["filename"])
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    subject_map = _provenance_subject_map(provenance)
    predicate = provenance.get("predicate") if isinstance(provenance.get("predicate"), dict) else {}
    definition = predicate.get("buildDefinition") if isinstance(predicate.get("buildDefinition"), dict) else {}
    external = definition.get("externalParameters") if isinstance(definition.get("externalParameters"), dict) else {}
    if external.get("applicationVersion") != version:
        raise ValueError("release provenance version does not match distribution index")
    source_fingerprint = str(index.get("sourceFingerprintSha256") or "")
    if subject_map.get("vulnflow-source-tree") != source_fingerprint:
        raise ValueError("source fingerprint does not match release provenance")

    provenance_links = {
        "python_wheel": ".whl",
        "source_distribution": f"{version}.tar.gz",
        "runtime_dependency_snapshot": "runtime_dependencies",
        "runtime_snapshot_manifest": "runtime_dependency_snapshot_manifest.json",
        "release_manifest": "reports/release_manifest.json",
        "cyclonedx_sbom": "bom.cdx.json",
    }
    for role, marker in provenance_links.items():
        digest = str(by_role[role]["sha256"])
        candidates = [value for name, value in subject_map.items() if marker in name]
        if candidates != [digest]:
            raise ValueError(f"release provenance linkage mismatch: {role}")

    return {
        "format": INDEX_FORMAT,
        "version": version,
        "artifacts_verified": len(verified),
        "source_fingerprint_sha256": source_fingerprint,
        "artifacts": verified,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a VulnFlow release distribution directory.")
    parser.add_argument("--directory", default=".")
    parser.add_argument("--index", default="release_distribution_index.json")
    parser.add_argument("--envelope", default="release_distribution_index.dsse.json")
    parser.add_argument("--public-key-file", default="release_distribution_public_key.txt")
    parser.add_argument("--expected-version", default="")
    args = parser.parse_args()

    directory = Path(args.directory).resolve()
    envelope = json.loads((directory / args.envelope).read_text(encoding="utf-8"))
    public_key = (directory / args.public_key_file).read_text(encoding="utf-8").strip()
    index = verify_envelope(envelope, public_key)
    index_path = directory / args.index
    if index_path.read_bytes() != canonical_json_bytes(index) + b"\n":
        raise SystemExit("release distribution index file does not match the signed DSSE payload")
    result = verify_directory(directory, index, expected_version=args.expected_version or None)
    print(
        f"VulnFlow {result['version']} release distribution verified: "
        f"{result['artifacts_verified']} artifacts"
    )


if __name__ == "__main__":
    main()
