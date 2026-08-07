from __future__ import annotations

"""Build and verify a signed, deterministic external-validation runner kit.

The v37 exchange authenticates a request and a returned response, but moving the
source tree, request bundle, requester key, and launch instructions as separate
files leaves room for accidental source/request mismatch and wrapper tampering.
This module packages those inputs into one deterministic ZIP and signs a
statement over an exact payload manifest with the requester's Ed25519 key.

A trusted copy of this verifier plus a separately pinned requester public key is
still required.  The verifier embedded in the kit is convenience code, not a
trust anchor.
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.public_signing import (
    ED25519_ALGORITHM,
    public_key_fingerprint,
    sign_ed25519,
    verify_ed25519,
)
from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_source_attestation import (
    copy_verified_public_source,
    require_public_source,
)
from scripts.external_validation_exchange import (
    REQUEST_JSON,
    REQUEST_SIGNATURE,
    _canonical,
    _parse_time,
    _read_json_object,
    _read_text,
    _sha256,
    _source_identity,
    load_private_key,
    load_public_key,
    verify_request_bundle,
)

KIT_FORMAT = "vulnflow-external-validation-runner-kit/2"
VERIFIER_FORMAT = "vulnflow-external-validation-runner-kit-verifier/1"
KIT_STATEMENT = "runner-kit-statement.json"
KIT_SIGNATURE = "runner-kit.ed25519"
KIT_MANIFEST = "KIT_SHA256SUMS.txt"
EMBEDDED_REQUESTER_KEY = "requester-public-key.json"
REQUEST_DIRECTORY = "request"
SOURCE_DIRECTORY = "source"
RUN_SH = "RUN_EXTERNAL_VALIDATION.sh"
RUN_PS1 = "RUN_EXTERNAL_VALIDATION.ps1"
README_FILE = "RUNNER_KIT_README.txt"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_ZIP_ENTRIES = 2_000
MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 32 * 1024 * 1024
MANIFEST_SEPARATOR = "  "

PAYLOAD_ROOTS = (
    REQUEST_DIRECTORY,
    SOURCE_DIRECTORY,
    EMBEDDED_REQUESTER_KEY,
    RUN_SH,
    RUN_PS1,
    README_FILE,
)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _safe_relative(value: str) -> bool:
    pure = PurePosixPath(value)
    return (
        bool(value)
        and value not in {".", ""}
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "\\" not in value
    )


def _read_public_manifest(root: Path) -> dict[str, str]:
    manifest = root / "SHA256SUMS.txt"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("source SHA256SUMS.txt is missing or not a regular file")
    entries: dict[str, str] = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        if len(line) < 67 or line[64:66] != MANIFEST_SEPARATOR:
            raise ValueError(f"invalid public manifest line {number}")
        digest, relative = line[:64], line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid public manifest digest at line {number}")
        if not _safe_relative(relative) or relative in entries:
            raise ValueError(f"unsafe or duplicate public manifest path at line {number}")
        entries[relative] = digest
    if not entries:
        raise ValueError("public source manifest is empty")
    return entries


def verify_public_source(root: Path) -> dict[str, Any]:
    root = root.resolve()
    entries = _read_public_manifest(root)
    issues: list[str] = []
    for relative, expected in entries.items():
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            current = candidate
            linked_component = False
            while current != root:
                if current.is_symlink():
                    linked_component = True
                    break
                current = current.parent
        except (OSError, ValueError):
            resolved = candidate
            linked_component = True
        if linked_component or not resolved.is_file():
            issues.append(f"missing, linked, or escaping source file: {relative}")
            continue
        if _sha256(resolved) != expected:
            issues.append(f"source hash mismatch: {relative}")
    return {
        "passed": not issues,
        "manifest_entries": len(entries),
        "issues": issues,
        "source_identity": _source_identity(root),
    }


def _require_new_file(path: Path, *, label: str) -> Path:
    raw = path.expanduser()
    if raw.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = raw.resolve()
    if resolved.exists():
        raise ValueError(f"{label} already exists: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _require_empty_directory(path: Path, *, label: str) -> Path:
    raw = path.expanduser()
    if raw.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = raw.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"{label} must be a directory path")
    if resolved.exists() and any(resolved.iterdir()):
        raise ValueError(f"{label} must be absent or empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _paths_overlap(first: Path, second: Path) -> bool:
    left = first.resolve()
    right = second.resolve()
    return left == right or left in right.parents or right in left.parents


def _payload_entries(
    *,
    source_root: Path,
    request_dir: Path,
    requester_public_key_file: Path,
) -> list[tuple[str, bytes, bool]]:
    source_root = source_root.resolve()
    request_dir = request_dir.resolve()
    requester_public_key_file = requester_public_key_file.resolve()

    source_result = verify_public_source(source_root)
    if not source_result["passed"]:
        raise ValueError("source tree does not match its public manifest: " + "; ".join(source_result["issues"][:5]))

    entries: list[tuple[str, bytes, bool]] = []
    public_entries = _read_public_manifest(source_root)
    for relative in sorted(public_entries):
        path = source_root / relative
        entries.append((f"{SOURCE_DIRECTORY}/{relative}", path.read_bytes(), os.access(path, os.X_OK)))
    entries.append((f"{SOURCE_DIRECTORY}/SHA256SUMS.txt", (source_root / "SHA256SUMS.txt").read_bytes(), False))

    for name in (REQUEST_JSON, REQUEST_SIGNATURE):
        path = request_dir / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"request bundle is missing {name}")
        entries.append((f"{REQUEST_DIRECTORY}/{name}", path.read_bytes(), False))

    if requester_public_key_file.is_symlink() or not requester_public_key_file.is_file():
        raise ValueError("requester public key must be a regular file")
    entries.append((EMBEDDED_REQUESTER_KEY, requester_public_key_file.read_bytes(), False))

    shell = """#!/usr/bin/env bash
set -euo pipefail
KIT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON_BIN" "$KIT_ROOT/source/scripts/external_validation_runner_kit.py" run-directory \
  --kit-root "$KIT_ROOT" "$@"
""".encode("utf-8")
    powershell = """$ErrorActionPreference = 'Stop'
$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
$env:PYTHONDONTWRITEBYTECODE = '1'
& $Python "$KitRoot/source/scripts/external_validation_runner_kit.py" run-directory --kit-root "$KitRoot" @args
exit $LASTEXITCODE
""".encode("utf-8")
    readme = """VulnFlow signed external-validation runner kit

Trust boundary:
- Verify this ZIP with a trusted verifier from this release and a requester public key obtained independently.
- The verifier and launchers inside this ZIP are convenience copies, not trust anchors.
- The operator private key must match the exact operator identity authorized by the signed request.
- Never place requester or operator private keys inside the kit.

After trusted extraction, run:
  ./RUN_EXTERNAL_VALIDATION.sh \
    --requester-public-key-file /independent/requester-public.json \
    --operator-private-key-file /secure/operator-private.json \
    --evidence-output-dir /output/external-evidence \
    --output-dir /output/signed-response \
    --runner-label approved-lab-operator \
    [--scanner-dir /approved/anonymized-scanners] [--chromium /path/to/chromium]

The command first re-verifies the extracted kit. Missing Docker, Chromium,
wheelhouse, or customer corpus remain non-passing evidence states.
""".encode("utf-8")
    entries.extend([
        (RUN_SH, shell, True),
        (RUN_PS1, powershell, False),
        (README_FILE, readme, False),
    ])
    return sorted(entries, key=lambda item: item[0])


def _manifest_bytes(entries: Iterable[tuple[str, bytes, bool]]) -> bytes:
    return ("\n".join(f"{_sha256_bytes(data)}  {name}" for name, data, _ in entries) + "\n").encode("utf-8")


def _zip_info(name: str, *, directory: bool, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | (0o755 if executable else 0o644))
    info.external_attr = mode << 16
    if directory:
        info.external_attr |= 0x10
    return info


def _write_zip(output: Path, *, root_name: str, entries: list[tuple[str, bytes, bool]]) -> None:
    directories = {root_name + "/"}
    for name, _, _ in entries:
        current = root_name
        for part in PurePosixPath(name).parts[:-1]:
            current += "/" + part
            directories.add(current + "/")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for directory in sorted(directories):
            archive.writestr(_zip_info(directory, directory=True), b"")
        for name, data, executable in sorted(entries, key=lambda item: item[0]):
            archive.writestr(_zip_info(f"{root_name}/{name}", directory=False, executable=executable), data)


def build_runner_kit(
    *,
    output_zip: Path,
    request_dir: Path,
    requester_private_key_file: Path,
    requester_public_key_file: Path,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    output = _require_new_file(output_zip, label="runner kit output")
    protected_inputs = [source_root, request_dir, requester_private_key_file, requester_public_key_file]
    if any(_paths_overlap(output, item) for item in protected_inputs):
        raise ValueError("runner kit output must be outside source, request, and key inputs")
    private_key_id, private_key, private_public = load_private_key(requester_private_key_file)
    public_key_id, pinned_public = load_public_key(requester_public_key_file)
    if private_key_id != public_key_id or private_public != pinned_public:
        raise ValueError("requester private and public key files do not match")

    request = verify_request_bundle(
        request_dir,
        requester_public_key_file=requester_public_key_file,
        source_root=source_root,
    )
    requester = request.get("requester")
    if not isinstance(requester, dict):
        raise ValueError("request has no requester identity")
    if requester.get("key_id") != public_key_id or requester.get("public_key_fingerprint") != public_key_fingerprint(pinned_public):
        raise ValueError("request is not signed by the supplied requester key")

    payload = _payload_entries(
        source_root=source_root,
        request_dir=request_dir,
        requester_public_key_file=requester_public_key_file,
    )
    payload_manifest = _manifest_bytes(payload)
    statement = {
        "format": KIT_FORMAT,
        "created_at": request["created_at"],
        "request_id": request["request_id"],
        "challenge_nonce": request["challenge_nonce"],
        "target_name": request["target_name"],
        "source_identity": request["source_identity"],
        "request_sha256": _sha256(request_dir / REQUEST_JSON),
        "request_signature_sha256": _sha256(request_dir / REQUEST_SIGNATURE),
        "requester": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": public_key_id,
            "public_key_fingerprint": public_key_fingerprint(pinned_public),
        },
        "authorized_operator": request["authorized_operator"],
        "required_checks": request["required_checks"],
        "parameters": request["parameters"],
        "payload_manifest_sha256": _sha256_bytes(payload_manifest),
        "payload_files": len(payload),
        "source_manifest_entries": verify_public_source(source_root)["manifest_entries"],
    }
    signature = sign_ed25519(private_key, _canonical(statement))
    final_entries = payload + [
        (KIT_MANIFEST, payload_manifest, False),
        (KIT_STATEMENT, json.dumps(statement, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n", False),
        (KIT_SIGNATURE, (signature + "\n").encode("ascii"), False),
    ]
    root_name = f"VulnFlow-External-Validation-{request['request_id']}"
    try:
        _write_zip(output, root_name=root_name, entries=final_entries)
        report = verify_runner_kit_archive(
            output,
            requester_public_key_file=requester_public_key_file,
            require_unexpired=True,
        )
        if not report["passed"]:
            raise ValueError("new runner kit failed self-verification: " + "; ".join(report["issues"]))
        return {
            "format": KIT_FORMAT,
            "output": str(output),
            "sha256": _sha256(output),
            "size": output.stat().st_size,
            "request_id": request["request_id"],
            "root": root_name,
            "payload_files": len(payload),
            "source_manifest_entries": statement["source_manifest_entries"],
            "verified": True,
        }
    except Exception:
        output.unlink(missing_ok=True)
        raise


def _safe_zip_inventory(archive: zipfile.ZipFile) -> tuple[str, list[zipfile.ZipInfo]]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError("runner kit ZIP entry count is invalid")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise ValueError("runner kit ZIP contains duplicate entries")
    roots: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\\" in name or not pure.parts:
            raise ValueError(f"unsafe runner kit ZIP path: {name}")
        roots.add(pure.parts[0])
        mode = (info.external_attr >> 16) & 0o170000
        if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise ValueError(f"runner kit ZIP contains a special file: {name}")
        if info.file_size > MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"runner kit ZIP member is too large: {name}")
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("runner kit ZIP expands beyond the allowed size")
        if info.date_time != ZIP_TIMESTAMP:
            raise ValueError("runner kit ZIP timestamp is not deterministic")
    if len(roots) != 1:
        raise ValueError("runner kit ZIP must contain one root directory")
    return next(iter(roots)), infos


def _extract_validated_zip(archive: zipfile.ZipFile, *, root_name: str, destination: Path) -> Path:
    for info in archive.infolist():
        relative_parts = PurePosixPath(info.filename).parts[1:]
        if not relative_parts:
            continue
        target = destination.joinpath(*relative_parts)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        data = archive.read(info)
        if len(data) != info.file_size:
            raise ValueError(f"runner kit ZIP member size changed while reading: {info.filename}")
        target.write_bytes(data)
        mode = (info.external_attr >> 16) & 0o777
        if os.name == "posix" and mode:
            target.chmod(mode & 0o755)
    return destination


def _load_kit_manifest(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("runner kit payload manifest is missing")
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if len(line) < 67 or line[64:66] != MANIFEST_SEPARATOR:
            raise ValueError(f"invalid runner kit manifest line {number}")
        digest, relative = line[:64], line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid runner kit manifest digest at line {number}")
        if not _safe_relative(relative) or relative in entries:
            raise ValueError(f"unsafe or duplicate runner kit manifest path at line {number}")
        entries[relative] = digest
    if not entries:
        raise ValueError("runner kit payload manifest is empty")
    return entries


def verify_runner_kit_directory(
    kit_root: Path,
    *,
    requester_public_key_file: Path,
    require_unexpired: bool = True,
) -> dict[str, Any]:
    root = kit_root.resolve()
    issues: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": "" if passed else detail})
        if not passed:
            issues.append(detail)

    if kit_root.is_symlink() or not root.is_dir():
        return {"format": VERIFIER_FORMAT, "passed": False, "checks": [], "issues": ["runner kit directory is missing or linked"]}

    symlinks = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_symlink()]
    check("no_symbolic_links", not symlinks, "runner kit directory contains symbolic links")

    expected_fixed = {KIT_MANIFEST, KIT_STATEMENT, KIT_SIGNATURE}
    actual_top = {path.name for path in root.iterdir()}
    expected_top = {REQUEST_DIRECTORY, SOURCE_DIRECTORY, EMBEDDED_REQUESTER_KEY, RUN_SH, RUN_PS1, README_FILE, *expected_fixed}
    check("top_level_inventory", actual_top == expected_top, "runner kit top-level inventory is unexpected")

    try:
        entries = _load_kit_manifest(root / KIT_MANIFEST)
        manifest_ok = True
    except (OSError, UnicodeError, ValueError) as exc:
        entries = {}
        manifest_ok = False
        issues.append(str(exc))
    actual_payload: dict[str, Path] = {}
    for name in PAYLOAD_ROOTS:
        base = root / name
        if base.is_file() and not base.is_symlink():
            actual_payload[name] = base
        elif base.is_dir() and not base.is_symlink():
            for path in base.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    actual_payload[path.relative_to(root).as_posix()] = path
    missing = sorted(set(entries) - set(actual_payload))
    extra = sorted(set(actual_payload) - set(entries))
    check("payload_inventory", manifest_ok and not missing and not extra, "runner kit payload inventory mismatch")
    mismatched = sorted(relative for relative, digest in entries.items() if relative in actual_payload and _sha256(actual_payload[relative]) != digest)
    check("payload_hashes", manifest_ok and not mismatched, "runner kit payload hash mismatch")

    try:
        statement = _read_json_object(root / KIT_STATEMENT, label="runner kit statement")
        signature = _read_text(root / KIT_SIGNATURE, label="runner kit signature")
        pinned_id, pinned_public = load_public_key(requester_public_key_file)
        embedded_id, embedded_public = load_public_key(root / EMBEDDED_REQUESTER_KEY)
        requester = statement.get("requester")
        identity_ok = (
            isinstance(requester, dict)
            and pinned_id == embedded_id
            and pinned_public == embedded_public
            and requester.get("algorithm") == ED25519_ALGORITHM
            and requester.get("key_id") == pinned_id
            and requester.get("public_key_fingerprint") == public_key_fingerprint(pinned_public)
        )
        signature_ok = verify_ed25519(
            signature_base64=signature,
            public_key_base64=pinned_public,
            payload=_canonical(statement),
        )
    except (OSError, TypeError, ValueError) as exc:
        statement = {}
        identity_ok = False
        signature_ok = False
        issues.append(f"runner kit signature verification failed: {exc}")
    check("requester_identity", identity_ok, "runner kit requester identity does not match the pinned key")
    check("kit_signature", signature_ok, "runner kit Ed25519 signature is invalid")

    try:
        request = verify_request_bundle(
            root / REQUEST_DIRECTORY,
            requester_public_key_file=requester_public_key_file,
            source_root=root / SOURCE_DIRECTORY,
            permit_expired_after_execution=None,
            now=None if require_unexpired else _parse_time(statement.get("created_at"), label="kit created_at"),
        )
        request_ok = True
    except (OSError, TypeError, ValueError) as exc:
        request = {}
        request_ok = False
        issues.append(f"runner kit request verification failed: {exc}")
    check("signed_request", request_ok, "runner kit request is invalid, expired, or bound to another source")

    try:
        source_result = verify_public_source(root / SOURCE_DIRECTORY)
    except (OSError, UnicodeError, ValueError) as exc:
        source_result = {"passed": False, "issues": [str(exc)], "manifest_entries": 0, "source_identity": {}}
        issues.append(f"runner kit source verification failed: {exc}")
    check("public_source_manifest", bool(source_result.get("passed")), "runner kit source tree does not match its public manifest")

    bindings_ok = False
    if statement and request and entries:
        bindings_ok = (
            statement.get("format") == KIT_FORMAT
            and statement.get("request_id") == request.get("request_id")
            and statement.get("challenge_nonce") == request.get("challenge_nonce")
            and statement.get("target_name") == request.get("target_name")
            and statement.get("source_identity") == request.get("source_identity")
            and statement.get("authorized_operator") == request.get("authorized_operator")
            and statement.get("request_sha256") == _sha256(root / REQUEST_DIRECTORY / REQUEST_JSON)
            and statement.get("request_signature_sha256") == _sha256(root / REQUEST_DIRECTORY / REQUEST_SIGNATURE)
            and statement.get("required_checks") == request.get("required_checks")
            and statement.get("parameters") == request.get("parameters")
            and statement.get("payload_manifest_sha256") == _sha256(root / KIT_MANIFEST)
            and statement.get("payload_files") == len(entries)
            and statement.get("source_manifest_entries") == source_result.get("manifest_entries")
            and statement.get("source_identity") == source_result.get("source_identity")
        )
    check("kit_bindings", bindings_ok, "runner kit statement does not bind its request, source, and payload exactly")

    passed = bool(checks) and all(item["passed"] for item in checks)
    return {
        "format": VERIFIER_FORMAT,
        "passed": passed,
        "request_id": str(statement.get("request_id") or ""),
        "target_name": str(statement.get("target_name") or ""),
        "source_identity": statement.get("source_identity") if isinstance(statement.get("source_identity"), dict) else {},
        "checks": checks,
        "issues": list(dict.fromkeys(item for item in issues if item)),
        "payload_files": len(actual_payload),
    }


def verify_runner_kit_archive(
    archive_path: Path,
    *,
    requester_public_key_file: Path,
    require_unexpired: bool = True,
) -> dict[str, Any]:
    path = archive_path.resolve()
    if archive_path.is_symlink() or not path.is_file():
        return {"format": VERIFIER_FORMAT, "passed": False, "checks": [], "issues": ["runner kit ZIP is missing or linked"]}
    try:
        with zipfile.ZipFile(path) as archive:
            root_name, _ = _safe_zip_inventory(archive)
            with tempfile.TemporaryDirectory(prefix="vulnflow-runner-kit-verify-") as temp_raw:
                extracted = Path(temp_raw) / root_name
                extracted.mkdir(parents=True)
                _extract_validated_zip(archive, root_name=root_name, destination=extracted)
                report = verify_runner_kit_directory(
                    extracted,
                    requester_public_key_file=requester_public_key_file,
                    require_unexpired=require_unexpired,
                )
                expected_root = f"VulnFlow-External-Validation-{report.get('request_id', '')}"
                root_ok = bool(report.get("request_id")) and root_name == expected_root
                report.setdefault("checks", []).append({
                    "name": "archive_root_binding",
                    "passed": root_ok,
                    "detail": "" if root_ok else "runner kit ZIP root does not match the signed request_id",
                })
                if not root_ok:
                    report.setdefault("issues", []).append("runner kit ZIP root does not match the signed request_id")
                    report["passed"] = False
                report["archive"] = str(path)
                report["archive_sha256"] = _sha256(path)
                report["root"] = root_name
                return report
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        return {"format": VERIFIER_FORMAT, "passed": False, "checks": [], "issues": [str(exc)], "archive": str(path)}


def extract_runner_kit(
    archive_path: Path,
    *,
    requester_public_key_file: Path,
    output_dir: Path,
) -> dict[str, Any]:
    report = verify_runner_kit_archive(
        archive_path,
        requester_public_key_file=requester_public_key_file,
        require_unexpired=True,
    )
    if not report.get("passed"):
        raise ValueError("runner kit verification failed before extraction: " + "; ".join(report.get("issues", [])))
    output = _require_empty_directory(output_dir, label="runner kit extraction directory")
    try:
        with zipfile.ZipFile(archive_path.resolve()) as archive:
            root_name, _ = _safe_zip_inventory(archive)
            target = output / root_name
            target.mkdir()
            _extract_validated_zip(archive, root_name=root_name, destination=target)
        post = verify_runner_kit_directory(
            target,
            requester_public_key_file=requester_public_key_file,
            require_unexpired=True,
        )
        if not post.get("passed"):
            raise ValueError("runner kit failed post-extraction verification")
        return {"passed": True, "output": str(target), "archive_sha256": _sha256(archive_path.resolve()), "verification": post}
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def run_extracted_kit(
    *,
    kit_root: Path,
    requester_public_key_file: Path,
    operator_private_key_file: Path,
    output_dir: Path,
    evidence_output_dir: Path,
    runner_label: str,
    scanner_dir: Path | None,
    chromium: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    verification = verify_runner_kit_directory(
        kit_root,
        requester_public_key_file=requester_public_key_file,
        require_unexpired=True,
    )
    if not verification.get("passed"):
        raise ValueError("runner kit directory failed verification: " + "; ".join(verification.get("issues", [])))
    kit = kit_root.resolve()
    source = kit / SOURCE_DIRECTORY
    request = kit / REQUEST_DIRECTORY
    request_payload = verify_request_bundle(
        request,
        requester_public_key_file=requester_public_key_file,
        source_root=source,
    )
    operator_key_id, _, operator_public = load_private_key(operator_private_key_file)
    authorized_operator = request_payload["authorized_operator"]
    if (
        authorized_operator.get("key_id") != operator_key_id
        or authorized_operator.get("public_key_fingerprint") != public_key_fingerprint(operator_public)
    ):
        raise ValueError("operator private key is not authorized by the signed runner-kit request")
    if _paths_overlap(output_dir, kit_root) or _paths_overlap(evidence_output_dir, kit_root):
        raise ValueError("execution outputs must be outside the runner kit")
    if _paths_overlap(output_dir, evidence_output_dir):
        raise ValueError("response and evidence outputs must not overlap")

    with tempfile.TemporaryDirectory(prefix="vulnflow-external-validation-snapshot-") as temporary:
        snapshot = Path(temporary) / "source"
        snapshot_attestation = copy_verified_public_source(source, snapshot)
        command = [
            sys.executable,
            str(snapshot / "scripts" / "external_validation_exchange.py"),
            "execute-request",
            "--request-dir",
            str(request),
            "--requester-public-key-file",
            str(requester_public_key_file),
            "--operator-private-key-file",
            str(operator_private_key_file),
            "--output-dir",
            str(output_dir),
            "--evidence-output-dir",
            str(evidence_output_dir),
            "--runner-label",
            runner_label,
            "--timeout-seconds",
            str(timeout_seconds),
        ]
        if scanner_dir is not None:
            command.extend(["--scanner-dir", str(scanner_dir)])
        if chromium:
            command.extend(["--chromium", chromium])
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(command, cwd=snapshot, env=env, check=False)
        snapshot_after = require_public_source(snapshot)
        if snapshot_after["identity"] != snapshot_attestation["identity"]:
            raise RuntimeError("verified execution snapshot changed during runner-kit execution")
        return {
            "kit_verification": verification,
            "execution_snapshot": {
                "format": snapshot_attestation["format"],
                "identity": snapshot_attestation["identity"],
                "verified_before_and_after": True,
            },
            "command": command,
            "exit_code": result.returncode,
        }, result.returncode


def _render(payload: dict[str, Any], output: Path | None = None) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    print(rendered, end="")
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-kit")
    create.add_argument("--request-dir", type=Path, required=True)
    create.add_argument("--requester-private-key-file", type=Path, required=True)
    create.add_argument("--requester-public-key-file", type=Path, required=True)
    create.add_argument("--output-zip", type=Path, required=True)

    verify = sub.add_parser("verify-kit")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--requester-public-key-file", type=Path, required=True)
    verify.add_argument("--allow-expired-for-audit", action="store_true")
    verify.add_argument("--json-output", type=Path)

    extract = sub.add_parser("extract-kit")
    extract.add_argument("archive", type=Path)
    extract.add_argument("--requester-public-key-file", type=Path, required=True)
    extract.add_argument("--output-dir", type=Path, required=True)

    verify_dir = sub.add_parser("verify-directory")
    verify_dir.add_argument("--kit-root", type=Path, required=True)
    verify_dir.add_argument("--requester-public-key-file", type=Path, required=True)
    verify_dir.add_argument("--allow-expired-for-audit", action="store_true")
    verify_dir.add_argument("--json-output", type=Path)

    run = sub.add_parser("run-directory")
    run.add_argument("--kit-root", type=Path, required=True)
    run.add_argument("--requester-public-key-file", type=Path, required=True)
    run.add_argument("--operator-private-key-file", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--evidence-output-dir", type=Path, required=True)
    run.add_argument("--runner-label", required=True)
    run.add_argument("--scanner-dir", type=Path)
    run.add_argument("--chromium", default="")
    run.add_argument("--timeout-seconds", type=int, default=3600)

    args = parser.parse_args()
    try:
        if args.command == "create-kit":
            _render(build_runner_kit(
                output_zip=args.output_zip,
                request_dir=args.request_dir,
                requester_private_key_file=args.requester_private_key_file,
                requester_public_key_file=args.requester_public_key_file,
            ))
            return 0
        if args.command == "verify-kit":
            report = verify_runner_kit_archive(
                args.archive,
                requester_public_key_file=args.requester_public_key_file,
                require_unexpired=not args.allow_expired_for_audit,
            )
            _render(report, args.json_output)
            return 0 if report.get("passed") else 1
        if args.command == "extract-kit":
            _render(extract_runner_kit(
                args.archive,
                requester_public_key_file=args.requester_public_key_file,
                output_dir=args.output_dir,
            ))
            return 0
        if args.command == "verify-directory":
            report = verify_runner_kit_directory(
                args.kit_root,
                requester_public_key_file=args.requester_public_key_file,
                require_unexpired=not args.allow_expired_for_audit,
            )
            _render(report, args.json_output)
            return 0 if report.get("passed") else 1
        if args.command == "run-directory":
            report, exit_code = run_extracted_kit(
                kit_root=args.kit_root,
                requester_public_key_file=args.requester_public_key_file,
                operator_private_key_file=args.operator_private_key_file,
                output_dir=args.output_dir,
                evidence_output_dir=args.evidence_output_dir,
                runner_label=args.runner_label,
                scanner_dir=args.scanner_dir,
                chromium=args.chromium,
                timeout_seconds=args.timeout_seconds,
            )
            _render(report)
            return exit_code
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"external validation runner kit failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
