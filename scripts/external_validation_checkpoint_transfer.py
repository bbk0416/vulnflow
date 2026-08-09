from __future__ import annotations

"""Deterministic signed transfer bundles for acceptance checkpoint series.

A checkpoint series is append-only and individually signed, but copying its
files directly is not a complete transfer protocol: an interrupted copy can
leave a shorter, still-valid prefix.  This module packages one exact series
head into a requester-signed deterministic ZIP and installs it monotonically.
Existing destinations can only stay at the same head or advance along the same
hash chain; stale and forked bundles are rejected.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.public_signing import ED25519_ALGORITHM, public_key_fingerprint, sign_ed25519, verify_ed25519
from scripts.external_validation_acceptance import (
    CHECKPOINTS_DIR,
    CHECKPOINT_SERIES_METADATA,
    REQUESTER_PUBLIC_KEY,
    ZERO_HASH,
    _canonical,
    _checkpoint_series_files,
    _requester_identity,
    initialize_checkpoint_series,
    verify_acceptance_checkpoint_series,
)
from scripts.external_validation_exchange import _read_json_object, _sha256, load_private_key, load_public_key

TRANSFER_FORMAT = "vulnflow-external-validation-checkpoint-series-transfer/1"
TRANSFER_VERIFIER_FORMAT = "vulnflow-external-validation-checkpoint-series-transfer-verifier/1"
TRANSFER_INSTALL_FORMAT = "vulnflow-external-validation-checkpoint-series-transfer-install/1"
TRANSFER_STATEMENT = "transfer-statement.json"
TRANSFER_SIGNATURE = "transfer-signature.ed25519"
SERIES_ROOT = "checkpoint-series"
ZIP_TIMESTAMP = (2026, 8, 4, 0, 0, 0)
MAX_ZIP_ENTRIES = 100_000
MAX_SINGLE_FILE_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def _require_new_file(path: Path, *, label: str) -> Path:
    raw = path.expanduser()
    if raw.is_symlink() or raw.exists():
        raise ValueError(f"{label} already exists or is unsafe")
    raw.parent.mkdir(parents=True, exist_ok=True)
    return raw.resolve()


def _series_inventory(series_dir: Path) -> list[dict[str, Any]]:
    root = series_dir.resolve()
    if series_dir.is_symlink() or not root.is_dir():
        raise ValueError("acceptance checkpoint series is missing or invalid")
    expected_top = {CHECKPOINT_SERIES_METADATA, REQUESTER_PUBLIC_KEY, CHECKPOINTS_DIR}
    if {path.name for path in root.iterdir()} != expected_top:
        raise ValueError("acceptance checkpoint series top-level inventory is invalid")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("acceptance checkpoint series contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("acceptance checkpoint series contains a non-regular file")
        relative = path.relative_to(root).as_posix()
        if not _safe_relative(relative):
            raise ValueError("acceptance checkpoint series contains an unsafe path")
        entries.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
    if len(entries) < 3:
        raise ValueError("acceptance checkpoint series inventory is incomplete")
    return entries


def _tree_sha256(entries: list[dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical({"entries": entries})).hexdigest()


def _zip_info(name: str, *, directory: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)
    info.external_attr = mode << 16
    if directory:
        info.external_attr |= 0x10
    return info


def _write_deterministic_zip(output: Path, *, root_name: str, entries: list[tuple[str, bytes]]) -> None:
    directories = {root_name + "/"}
    for name, _ in entries:
        current = root_name
        for part in PurePosixPath(name).parts[:-1]:
            current += "/" + part
            directories.add(current + "/")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for directory in sorted(directories):
            archive.writestr(_zip_info(directory, directory=True), b"")
        for name, data in sorted(entries):
            archive.writestr(_zip_info(f"{root_name}/{name}", directory=False), data)


def build_checkpoint_series_transfer(
    series_dir: Path,
    *,
    requester_private_key_file: Path,
    requester_public_key_file: Path,
    output_zip: Path,
) -> dict[str, Any]:
    output = _require_new_file(output_zip, label="checkpoint series transfer output")
    requester_key_id, requester_private, requester_public = load_private_key(requester_private_key_file)
    pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
    if requester_key_id != pinned_key_id or requester_public != pinned_public:
        raise ValueError("requester private key does not match the pinned requester public key")
    report = verify_acceptance_checkpoint_series(series_dir, requester_public_key_file=requester_public_key_file)
    if report.get("passed") is not True or int(report.get("checkpoint_count") or 0) < 1:
        raise ValueError("acceptance checkpoint series failed integrity verification or is empty")
    inventory = _series_inventory(series_dir)
    latest = report["latest_checkpoint"]
    statement = {
        "format": TRANSFER_FORMAT,
        "requester": _requester_identity(requester_public_key_file),
        "checkpoint_count": report["checkpoint_count"],
        "head_checkpoint_sha256": report["head_checkpoint_sha256"],
        "head_generation": latest["generation"],
        "head_receipt_count": latest["receipt_count"],
        "head_receipt_sha256": latest["head_receipt_sha256"],
        "series_tree_sha256": _tree_sha256(inventory),
        "series_file_count": len(inventory),
        "series_inventory": inventory,
    }
    signature = sign_ed25519(requester_private, _canonical(statement))
    root_name = f"VulnFlow-Acceptance-Checkpoint-Series-{str(report['head_checkpoint_sha256'])[:16]}"
    entries: list[tuple[str, bytes]] = []
    root = series_dir.resolve()
    for item in inventory:
        relative = str(item["path"])
        entries.append((f"{SERIES_ROOT}/{relative}", (root / relative).read_bytes()))
    entries.extend(
        [
            (TRANSFER_STATEMENT, json.dumps(statement, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"),
            (TRANSFER_SIGNATURE, (signature + "\n").encode("ascii")),
        ]
    )
    try:
        _write_deterministic_zip(output, root_name=root_name, entries=entries)
        verified = verify_checkpoint_series_transfer(output, requester_public_key_file=requester_public_key_file)
        if verified.get("passed") is not True:
            raise ValueError("new checkpoint series transfer failed self-verification: " + "; ".join(verified.get("issues") or []))
        return {
            "format": TRANSFER_FORMAT,
            "output": str(output),
            "sha256": _sha256(output),
            "size": output.stat().st_size,
            "checkpoint_count": statement["checkpoint_count"],
            "head_checkpoint_sha256": statement["head_checkpoint_sha256"],
            "series_tree_sha256": statement["series_tree_sha256"],
            "verified": True,
        }
    except Exception:
        output.unlink(missing_ok=True)
        raise


def _safe_zip_inventory(archive: zipfile.ZipFile) -> tuple[str, list[zipfile.ZipInfo]]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError("checkpoint series transfer ZIP entry count is invalid")
    names = [item.filename for item in infos]
    if len(names) != len(set(names)):
        raise ValueError("checkpoint series transfer ZIP contains duplicate entries")
    roots: set[str] = set()
    total = 0
    for info in infos:
        pure = PurePosixPath(info.filename)
        if pure.is_absolute() or ".." in pure.parts or "\\" in info.filename or not pure.parts:
            raise ValueError(f"unsafe checkpoint series transfer ZIP path: {info.filename}")
        roots.add(pure.parts[0])
        mode = (info.external_attr >> 16) & 0o170000
        if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise ValueError(f"checkpoint series transfer ZIP contains a special file: {info.filename}")
        if info.file_size > MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"checkpoint series transfer ZIP member is too large: {info.filename}")
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("checkpoint series transfer ZIP expands beyond the allowed size")
        if info.date_time != ZIP_TIMESTAMP:
            raise ValueError("checkpoint series transfer ZIP timestamp is not deterministic")
    if len(roots) != 1:
        raise ValueError("checkpoint series transfer ZIP must contain one root directory")
    return next(iter(roots)), infos


def _extract_archive(archive: zipfile.ZipFile, *, destination: Path) -> Path:
    root_name, infos = _safe_zip_inventory(archive)
    for info in infos:
        parts = PurePosixPath(info.filename).parts[1:]
        if not parts:
            continue
        target = destination.joinpath(*parts)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        data = archive.read(info)
        if len(data) != info.file_size:
            raise ValueError(f"checkpoint series transfer member size changed while reading: {info.filename}")
        target.write_bytes(data)
        if os.name == "posix":
            target.chmod(0o644)
    return destination


def _verify_extracted_transfer(root: Path, *, requester_public_key_file: Path) -> dict[str, Any]:
    issues: list[str] = []
    statement: dict[str, Any] = {}
    series_report: dict[str, Any] = {}
    try:
        expected_top = {TRANSFER_STATEMENT, TRANSFER_SIGNATURE, SERIES_ROOT}
        if {path.name for path in root.iterdir()} != expected_top:
            raise ValueError("checkpoint series transfer top-level inventory is invalid")
        statement = _read_json_object(root / TRANSFER_STATEMENT, label="checkpoint series transfer statement")
        signature = (root / TRANSFER_SIGNATURE).read_text(encoding="ascii").strip()
        if statement.get("format") != TRANSFER_FORMAT:
            raise ValueError("checkpoint series transfer statement format is invalid")
        pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
        identity = {
            "algorithm": ED25519_ALGORITHM,
            "key_id": pinned_key_id,
            "public_key_fingerprint": public_key_fingerprint(pinned_public),
        }
        if statement.get("requester") != identity:
            raise ValueError("checkpoint series transfer requester identity is invalid")
        if not verify_ed25519(signature_base64=signature, public_key_base64=pinned_public, payload=_canonical(statement)):
            raise ValueError("checkpoint series transfer signature is invalid")
        inventory = _series_inventory(root / SERIES_ROOT)
        if statement.get("series_inventory") != inventory:
            raise ValueError("checkpoint series transfer inventory does not match the signed statement")
        if statement.get("series_file_count") != len(inventory):
            raise ValueError("checkpoint series transfer file count is invalid")
        if statement.get("series_tree_sha256") != _tree_sha256(inventory):
            raise ValueError("checkpoint series transfer tree hash is invalid")
        series_report = verify_acceptance_checkpoint_series(root / SERIES_ROOT, requester_public_key_file=requester_public_key_file)
        if series_report.get("passed") is not True:
            raise ValueError("embedded checkpoint series failed integrity verification")
        latest = series_report.get("latest_checkpoint")
        if not isinstance(latest, dict):
            raise ValueError("embedded checkpoint series is empty")
        expected = {
            "checkpoint_count": series_report["checkpoint_count"],
            "head_checkpoint_sha256": series_report["head_checkpoint_sha256"],
            "head_generation": latest["generation"],
            "head_receipt_count": latest["receipt_count"],
            "head_receipt_sha256": latest["head_receipt_sha256"],
        }
        for key, value in expected.items():
            if statement.get(key) != value:
                raise ValueError(f"checkpoint series transfer {key} does not match the embedded series")
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        issues.append(str(exc))
    return {
        "format": TRANSFER_VERIFIER_FORMAT,
        "passed": not issues,
        "statement": statement,
        "series": series_report,
        "issues": issues,
    }


def verify_checkpoint_series_transfer(
    transfer_zip: Path,
    *,
    requester_public_key_file: Path,
) -> dict[str, Any]:
    path = transfer_zip.resolve()
    if transfer_zip.is_symlink() or not path.is_file():
        return {"format": TRANSFER_VERIFIER_FORMAT, "passed": False, "issues": ["checkpoint series transfer is missing or invalid"]}
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow-checkpoint-transfer-verify-") as temporary:
            extracted = Path(temporary)
            with zipfile.ZipFile(path) as archive:
                _extract_archive(archive, destination=extracted)
            report = _verify_extracted_transfer(extracted, requester_public_key_file=requester_public_key_file)
            report["transfer_sha256"] = _sha256(path)
            return report
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return {"format": TRANSFER_VERIFIER_FORMAT, "passed": False, "issues": [str(exc)]}


def _publish_bytes_exclusive_or_match(path: Path, data: bytes) -> bool:
    """Publish immutable bytes; return True when this call created the file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise ValueError("checkpoint series destination contains a conflicting immutable file")
        return False
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o644)
        try:
            os.link(temporary, path)
            created = True
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise ValueError("checkpoint series destination changed concurrently or forked")
            created = False
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return created
    finally:
        temporary.unlink(missing_ok=True)


def install_checkpoint_series_transfer(
    transfer_zip: Path,
    *,
    series_dir: Path,
    requester_public_key_file: Path,
) -> dict[str, Any]:
    verification = verify_checkpoint_series_transfer(transfer_zip, requester_public_key_file=requester_public_key_file)
    if verification.get("passed") is not True:
        raise ValueError("checkpoint series transfer failed verification: " + "; ".join(verification.get("issues") or []))
    with tempfile.TemporaryDirectory(prefix="vulnflow-checkpoint-transfer-install-") as temporary:
        extracted = Path(temporary)
        with zipfile.ZipFile(transfer_zip.resolve()) as archive:
            _extract_archive(archive, destination=extracted)
        incoming_root = extracted / SERIES_ROOT
        incoming_report = verify_acceptance_checkpoint_series(incoming_root, requester_public_key_file=requester_public_key_file)
        destination = initialize_checkpoint_series(series_dir, requester_public_key_file=requester_public_key_file)
        current_report = verify_acceptance_checkpoint_series(destination, requester_public_key_file=requester_public_key_file)
        if current_report.get("passed") is not True:
            raise ValueError("destination checkpoint series failed integrity verification")
        current_count = int(current_report.get("checkpoint_count") or 0)
        incoming_count = int(incoming_report.get("checkpoint_count") or 0)
        if incoming_count < current_count:
            raise ValueError("checkpoint series transfer is older than the installed destination")
        incoming_files = _checkpoint_series_files(incoming_root / CHECKPOINTS_DIR)
        current_files = _checkpoint_series_files(destination / CHECKPOINTS_DIR)
        for generation in range(current_count):
            if _sha256(current_files[generation]) != _sha256(incoming_files[generation]):
                raise ValueError("checkpoint series transfer does not extend the installed destination")
        added = 0
        for path in incoming_files[current_count:]:
            target = destination / CHECKPOINTS_DIR / path.name
            if _publish_bytes_exclusive_or_match(target, path.read_bytes()):
                added += 1
        final = verify_acceptance_checkpoint_series(destination, requester_public_key_file=requester_public_key_file)
        if final.get("passed") is not True:
            raise RuntimeError("installed checkpoint series failed integrity verification")
        final_files = _checkpoint_series_files(destination / CHECKPOINTS_DIR)
        if len(final_files) < incoming_count:
            raise RuntimeError("checkpoint series transfer installation stopped before the signed head")
        for generation in range(incoming_count):
            if _sha256(final_files[generation]) != _sha256(incoming_files[generation]):
                raise RuntimeError("installed checkpoint series does not contain the signed transfer prefix")
        return {
            "format": TRANSFER_INSTALL_FORMAT,
            "passed": True,
            "transfer_sha256": verification.get("transfer_sha256"),
            "incoming_checkpoint_count": incoming_count,
            "incoming_head_checkpoint_sha256": incoming_report["head_checkpoint_sha256"],
            "installed_checkpoint_count": final["checkpoint_count"],
            "installed_head_checkpoint_sha256": final["head_checkpoint_sha256"],
            "checkpoints_added": added,
            "idempotent": added == 0 and current_count == incoming_count,
        }


def _render(payload: dict[str, Any], output: Path | None = None) -> None:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    print(text, end="")
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build-transfer")
    build.add_argument("series_dir", type=Path)
    build.add_argument("--requester-private-key-file", type=Path, required=True)
    build.add_argument("--requester-public-key-file", type=Path, required=True)
    build.add_argument("--output-zip", type=Path, required=True)
    build.add_argument("--json-output", type=Path)

    verify = sub.add_parser("verify-transfer")
    verify.add_argument("transfer_zip", type=Path)
    verify.add_argument("--requester-public-key-file", type=Path, required=True)
    verify.add_argument("--json-output", type=Path)

    install = sub.add_parser("install-transfer")
    install.add_argument("transfer_zip", type=Path)
    install.add_argument("--series-dir", type=Path, required=True)
    install.add_argument("--requester-public-key-file", type=Path, required=True)
    install.add_argument("--json-output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "build-transfer":
            report = build_checkpoint_series_transfer(
                args.series_dir,
                requester_private_key_file=args.requester_private_key_file,
                requester_public_key_file=args.requester_public_key_file,
                output_zip=args.output_zip,
            )
            _render(report, args.json_output)
            return 0
        if args.command == "verify-transfer":
            report = verify_checkpoint_series_transfer(args.transfer_zip, requester_public_key_file=args.requester_public_key_file)
            _render(report, args.json_output)
            return 0 if report.get("passed") is True else 1
        if args.command == "install-transfer":
            report = install_checkpoint_series_transfer(
                args.transfer_zip,
                series_dir=args.series_dir,
                requester_public_key_file=args.requester_public_key_file,
            )
            _render(report, args.json_output)
            return 0
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"checkpoint series transfer failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
