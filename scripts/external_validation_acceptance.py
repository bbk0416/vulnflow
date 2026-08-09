from __future__ import annotations

"""Requester-signed single-acceptance ledger for external-validation responses.

A detached response signature proves who produced a response, but a stateless
verifier cannot tell whether the same response was replayed or whether an
operator produced two different valid responses for one request.  This module
turns verification into an explicit requester-side acceptance decision.  Each
accepted request is recorded exactly once in an append-only Ed25519-signed hash
chain.  Replays and conflicting second responses are rejected before a new
receipt is published.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.public_signing import (
    ED25519_ALGORITHM,
    public_key_fingerprint,
    sign_ed25519,
    verify_ed25519,
)
from scripts.external_validation_exchange import (
    OPERATOR_PUBLIC_KEY,
    REQUEST_JSON,
    REQUEST_SIGNATURE,
    RESPONSE_JSON,
    RESPONSE_SIGNATURE,
    _canonical,
    _iso,
    _read_json_object,
    _sha256,
    _utc_now,
    load_private_key,
    load_public_key,
    verify_request_bundle,
    verify_response_bundle,
)

LEDGER_FORMAT = "vulnflow-external-validation-acceptance-ledger/1"
RECEIPT_FORMAT = "vulnflow-external-validation-acceptance-receipt/1"
ENVELOPE_FORMAT = "vulnflow-external-validation-acceptance-envelope/1"
VERIFIER_FORMAT = "vulnflow-external-validation-acceptance-verifier/1"
CHECKPOINT_FORMAT = "vulnflow-external-validation-acceptance-checkpoint/1"
CHECKPOINT_ENVELOPE_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-envelope/1"
CHECKPOINT_VERIFIER_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-verifier/1"
CHECKPOINT_SERIES_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-series/1"
CHECKPOINT_SERIES_ENTRY_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-series-entry/1"
CHECKPOINT_SERIES_ENVELOPE_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-series-envelope/1"
CHECKPOINT_SERIES_VERIFIER_FORMAT = "vulnflow-external-validation-acceptance-checkpoint-series-verifier/1"
CHECKPOINT_SERIES_METADATA = "checkpoint-series.json"
CHECKPOINTS_DIR = "checkpoints"
CHECKPOINT_SERIES_RE = re.compile(r"^([0-9]{8})\.checkpoint\.json$")
LEDGER_METADATA = "ledger.json"
REQUESTER_PUBLIC_KEY = "requester-public-key.json"
RECEIPTS_DIR = "receipts"
RECEIPT_RE = re.compile(r"^([0-9]{8})\.receipt\.json$")
ZERO_HASH = "0" * 64


def _write_json_atomic(path: Path, payload: dict[str, Any], *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(mode)
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _publish_exclusive(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o644)
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ValueError("acceptance ledger changed concurrently; retry the operation") from exc
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def response_tree_identity(response_dir: Path) -> dict[str, Any]:
    root = response_dir.resolve()
    if response_dir.is_symlink() or not root.is_dir():
        raise ValueError("response bundle must be a regular directory")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("response bundle contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("response bundle contains a non-regular file")
        relative = path.relative_to(root).as_posix()
        if not _safe_relative(relative):
            raise ValueError("response bundle contains an unsafe path")
        entries.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
    if not entries:
        raise ValueError("response bundle is empty")
    digest = hashlib.sha256(_canonical({"entries": entries})).hexdigest()
    return {"file_count": len(entries), "tree_sha256": digest}


def _requester_identity(public_key_file: Path) -> dict[str, str]:
    key_id, public_key = load_public_key(public_key_file)
    return {
        "algorithm": ED25519_ALGORITHM,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint(public_key),
    }


def verify_acceptance_checkpoint(
    checkpoint_file: Path,
    *,
    requester_public_key_file: Path,
) -> dict[str, Any]:
    issues: list[str] = []
    statement: dict[str, Any] = {}
    try:
        if checkpoint_file.is_symlink() or not checkpoint_file.is_file():
            raise ValueError("acceptance checkpoint must be a regular file")
        envelope = _read_json_object(checkpoint_file, label="acceptance checkpoint envelope")
        candidate = envelope.get("statement")
        signature = str(envelope.get("signature_base64") or "")
        if envelope.get("format") != CHECKPOINT_ENVELOPE_FORMAT or not isinstance(candidate, dict):
            raise ValueError("acceptance checkpoint envelope format is invalid")
        if candidate.get("format") != CHECKPOINT_FORMAT:
            raise ValueError("acceptance checkpoint statement format is invalid")
        identity = _requester_identity(requester_public_key_file)
        if candidate.get("requester") != identity:
            raise ValueError("acceptance checkpoint requester identity is invalid")
        _, public_key = load_public_key(requester_public_key_file)
        if not verify_ed25519(
            signature_base64=signature,
            public_key_base64=public_key,
            payload=_canonical(candidate),
        ):
            raise ValueError("acceptance checkpoint signature is invalid")
        receipt_count = candidate.get("receipt_count")
        if not isinstance(receipt_count, int) or receipt_count < 1:
            raise ValueError("acceptance checkpoint receipt_count is invalid")
        if candidate.get("accepted_request_count") != receipt_count:
            raise ValueError("acceptance checkpoint accepted_request_count is invalid")
        head_hash = str(candidate.get("head_receipt_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", head_hash) or head_hash == ZERO_HASH:
            raise ValueError("acceptance checkpoint head receipt hash is invalid")
        head_request_id = str(candidate.get("head_request_id") or "")
        if not re.fullmatch(r"[0-9a-f]{32}", head_request_id):
            raise ValueError("acceptance checkpoint head request_id is invalid")
        head_response_hash = str(candidate.get("head_response_tree_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", head_response_hash):
            raise ValueError("acceptance checkpoint head response identity is invalid")
        created_at = str(candidate.get("created_at") or "")
        parsed = datetime.fromisoformat(created_at[:-1] + "+00:00" if created_at.endswith("Z") else created_at)
        if parsed.tzinfo is None:
            raise ValueError("acceptance checkpoint created_at must include a timezone")
        statement = candidate
    except (OSError, ValueError, TypeError) as exc:
        issues.append(str(exc))
    return {
        "format": CHECKPOINT_VERIFIER_FORMAT,
        "passed": not issues,
        "checkpoint_sha256": _sha256(checkpoint_file) if not issues else None,
        "statement": statement,
        "issues": issues,
    }


def create_acceptance_checkpoint(
    ledger_dir: Path,
    *,
    requester_private_key_file: Path,
    requester_public_key_file: Path,
    output_file: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    requester_key_id, requester_private, requester_public = load_private_key(requester_private_key_file)
    pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
    if requester_key_id != pinned_key_id or requester_public != pinned_public:
        raise ValueError("requester private key does not match the pinned requester public key")
    ledger_report = verify_acceptance_ledger(
        ledger_dir,
        requester_public_key_file=requester_public_key_file,
    )
    if ledger_report.get("passed") is not True:
        raise ValueError("acceptance ledger failed integrity verification")
    entries = ledger_report.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("acceptance ledger has no receipt to checkpoint")
    head = entries[-1]
    statement = {
        "format": CHECKPOINT_FORMAT,
        "created_at": _iso((now or _utc_now()).astimezone(timezone.utc)),
        "requester": _requester_identity(requester_public_key_file),
        "receipt_count": ledger_report["receipt_count"],
        "accepted_request_count": len(ledger_report["accepted_requests"]),
        "head_receipt_sha256": ledger_report["head_receipt_sha256"],
        "head_request_id": head["request_id"],
        "head_response_tree_sha256": head["response_tree_sha256"],
    }
    envelope = {
        "format": CHECKPOINT_ENVELOPE_FORMAT,
        "statement": statement,
        "signature_base64": sign_ed25519(requester_private, _canonical(statement)),
    }
    raw_output = output_file.expanduser()
    if raw_output.is_symlink() or raw_output.exists():
        raise ValueError("acceptance checkpoint output already exists or is unsafe")
    resolved_output = raw_output.resolve()
    try:
        resolved_output.relative_to(ledger_dir.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("acceptance checkpoint must be stored outside the acceptance ledger")
    _publish_exclusive(resolved_output, envelope)
    report = verify_acceptance_checkpoint(
        resolved_output,
        requester_public_key_file=requester_public_key_file,
    )
    if report.get("passed") is not True:
        raise RuntimeError("published acceptance checkpoint failed verification")
    return report


def _receipt_files(receipts_dir: Path) -> list[Path]:
    if receipts_dir.is_symlink() or not receipts_dir.is_dir():
        raise ValueError("acceptance receipts directory is missing or invalid")
    files: list[Path] = []
    for path in receipts_dir.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("acceptance receipts directory contains a non-regular entry")
        if not RECEIPT_RE.fullmatch(path.name):
            raise ValueError("acceptance receipts directory contains an unexpected file")
        files.append(path)
    return sorted(files)



def _checkpoint_series_files(checkpoints_dir: Path) -> list[Path]:
    if checkpoints_dir.is_symlink() or not checkpoints_dir.is_dir():
        raise ValueError("acceptance checkpoint series directory is missing or invalid")
    files: list[Path] = []
    for path in checkpoints_dir.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("acceptance checkpoint series contains a non-regular entry")
        if not CHECKPOINT_SERIES_RE.fullmatch(path.name):
            raise ValueError("acceptance checkpoint series contains an unexpected file")
        files.append(path)
    return sorted(files)


def initialize_checkpoint_series(series_dir: Path, *, requester_public_key_file: Path) -> Path:
    raw = series_dir.expanduser()
    if raw.is_symlink():
        raise ValueError("acceptance checkpoint series must not be a symbolic link")
    root = raw.resolve()
    if root.exists() and not root.is_dir():
        raise ValueError("acceptance checkpoint series path must be a directory")
    root.mkdir(parents=True, exist_ok=True)
    expected = {CHECKPOINT_SERIES_METADATA, REQUESTER_PUBLIC_KEY, CHECKPOINTS_DIR}
    if any(root.iterdir()):
        if {path.name for path in root.iterdir()} != expected:
            raise ValueError("acceptance checkpoint series inventory is invalid")
        return root
    key_payload = _read_json_object(requester_public_key_file, label="requester public key")
    if "private_key_base64" in key_payload:
        raise ValueError("acceptance checkpoint series must not embed requester private key material")
    identity = _requester_identity(requester_public_key_file)
    _write_json_atomic(root / CHECKPOINT_SERIES_METADATA, {"format": CHECKPOINT_SERIES_FORMAT, "requester": identity})
    _write_json_atomic(root / REQUESTER_PUBLIC_KEY, key_payload)
    (root / CHECKPOINTS_DIR).mkdir(mode=0o755)
    return root


def verify_acceptance_checkpoint_series(
    series_dir: Path,
    *,
    requester_public_key_file: Path,
) -> dict[str, Any]:
    root = series_dir.resolve()
    issues: list[str] = []
    entries: list[dict[str, Any]] = []
    if series_dir.is_symlink() or not root.is_dir():
        return {"format": CHECKPOINT_SERIES_VERIFIER_FORMAT, "passed": False, "issues": ["acceptance checkpoint series is missing or invalid"], "entries": []}
    expected_top = {CHECKPOINT_SERIES_METADATA, REQUESTER_PUBLIC_KEY, CHECKPOINTS_DIR}
    if {path.name for path in root.iterdir()} != expected_top:
        issues.append("acceptance checkpoint series top-level inventory is invalid")
    try:
        pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
        embedded_key_id, embedded_public = load_public_key(root / REQUESTER_PUBLIC_KEY)
        metadata = _read_json_object(root / CHECKPOINT_SERIES_METADATA, label="acceptance checkpoint series metadata")
        identity = {"algorithm": ED25519_ALGORITHM, "key_id": pinned_key_id, "public_key_fingerprint": public_key_fingerprint(pinned_public)}
        if embedded_key_id != pinned_key_id or embedded_public != pinned_public:
            issues.append("embedded requester public key does not match the pinned key")
        if metadata.get("format") != CHECKPOINT_SERIES_FORMAT or metadata.get("requester") != identity:
            issues.append("acceptance checkpoint series metadata does not match the pinned requester")
        files = _checkpoint_series_files(root / CHECKPOINTS_DIR)
    except (OSError, ValueError) as exc:
        issues.append(str(exc)); files=[]; pinned_public=""; identity={}
    previous_hash = ZERO_HASH
    previous_receipt_count = 0
    checkpoint_hashes: list[str] = []
    for generation, path in enumerate(files, 1):
        try:
            envelope = _read_json_object(path, label="acceptance checkpoint series envelope")
            statement = envelope.get("statement")
            signature = str(envelope.get("signature_base64") or "")
            if envelope.get("format") != CHECKPOINT_SERIES_ENVELOPE_FORMAT or not isinstance(statement, dict):
                raise ValueError("acceptance checkpoint series envelope format is invalid")
            if statement.get("format") != CHECKPOINT_SERIES_ENTRY_FORMAT:
                raise ValueError("acceptance checkpoint series entry format is invalid")
            if statement.get("generation") != generation:
                raise ValueError("acceptance checkpoint generation is not contiguous")
            if statement.get("previous_checkpoint_sha256") != previous_hash:
                raise ValueError("acceptance checkpoint series hash chain is invalid")
            if statement.get("requester") != identity:
                raise ValueError("acceptance checkpoint requester identity is invalid")
            if not verify_ed25519(signature_base64=signature, public_key_base64=pinned_public, payload=_canonical(statement)):
                raise ValueError("acceptance checkpoint series signature is invalid")
            receipt_count = statement.get("receipt_count")
            if not isinstance(receipt_count, int) or receipt_count <= previous_receipt_count:
                raise ValueError("acceptance checkpoint receipt_count must increase")
            for name, pattern in (("head_receipt_sha256", r"[0-9a-f]{64}"), ("head_request_id", r"[0-9a-f]{32}"), ("head_response_tree_sha256", r"[0-9a-f]{64}")):
                if not re.fullmatch(pattern, str(statement.get(name) or "")):
                    raise ValueError(f"acceptance checkpoint {name} is invalid")
            previous_receipt_count = receipt_count
            previous_hash = _sha256(path)
            checkpoint_hashes.append(previous_hash)
            entries.append(statement)
        except (OSError, ValueError, TypeError) as exc:
            issues.append(f"{path.name}: {exc}"); break
    return {
        "format": CHECKPOINT_SERIES_VERIFIER_FORMAT,
        "passed": not issues,
        "requester": identity,
        "checkpoint_count": len(entries),
        "head_checkpoint_sha256": previous_hash,
        "entries": entries,
        "latest_checkpoint": entries[-1] if entries else None,
        "issues": issues,
    }


def append_acceptance_checkpoint_series(
    ledger_dir: Path,
    *,
    series_dir: Path,
    requester_private_key_file: Path,
    requester_public_key_file: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    requester_key_id, requester_private, requester_public = load_private_key(requester_private_key_file)
    pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
    if requester_key_id != pinned_key_id or requester_public != pinned_public:
        raise ValueError("requester private key does not match the pinned requester public key")
    root = initialize_checkpoint_series(series_dir, requester_public_key_file=requester_public_key_file)
    series_report = verify_acceptance_checkpoint_series(root, requester_public_key_file=requester_public_key_file)
    if series_report.get("passed") is not True:
        raise ValueError("acceptance checkpoint series failed integrity verification")
    minimum = series_report.get("latest_checkpoint")
    ledger_report = verify_acceptance_ledger(
        ledger_dir,
        requester_public_key_file=requester_public_key_file,
        minimum_checkpoint_statement=minimum,
    )
    if ledger_report.get("passed") is not True:
        raise ValueError("acceptance ledger does not extend the checkpoint series head")
    if ledger_report.get("receipt_count", 0) < 1:
        raise ValueError("acceptance ledger has no receipt to checkpoint")
    prior_count = int(minimum["receipt_count"]) if isinstance(minimum, dict) else 0
    if int(ledger_report["receipt_count"]) <= prior_count:
        raise ValueError("acceptance checkpoint series has no new receipt to checkpoint")
    head = ledger_report["entries"][-1]
    generation = int(series_report["checkpoint_count"]) + 1
    statement = {
        "format": CHECKPOINT_SERIES_ENTRY_FORMAT,
        "generation": generation,
        "previous_checkpoint_sha256": series_report["head_checkpoint_sha256"],
        "created_at": _iso((now or _utc_now()).astimezone(timezone.utc)),
        "requester": _requester_identity(requester_public_key_file),
        "receipt_count": ledger_report["receipt_count"],
        "accepted_request_count": len(ledger_report["accepted_requests"]),
        "head_receipt_sha256": ledger_report["head_receipt_sha256"],
        "head_request_id": head["request_id"],
        "head_response_tree_sha256": head["response_tree_sha256"],
    }
    envelope = {"format": CHECKPOINT_SERIES_ENVELOPE_FORMAT, "statement": statement, "signature_base64": sign_ed25519(requester_private, _canonical(statement))}
    final_path = root / CHECKPOINTS_DIR / f"{generation:08d}.checkpoint.json"
    _publish_exclusive(final_path, envelope)
    final = verify_acceptance_checkpoint_series(root, requester_public_key_file=requester_public_key_file)
    if final.get("passed") is not True or final.get("checkpoint_count") != generation:
        raise RuntimeError("published acceptance checkpoint failed series verification")
    return {"appended": True, "checkpoint_file": str(final_path), "checkpoint_sha256": _sha256(final_path), "statement": statement, "series": {"checkpoint_count": final["checkpoint_count"], "head_checkpoint_sha256": final["head_checkpoint_sha256"]}}

def initialize_ledger(ledger_dir: Path, *, requester_public_key_file: Path) -> Path:
    raw = ledger_dir.expanduser()
    if raw.is_symlink():
        raise ValueError("acceptance ledger directory must not be a symbolic link")
    root = raw.resolve()
    if root.exists() and not root.is_dir():
        raise ValueError("acceptance ledger path must be a directory")
    root.mkdir(parents=True, exist_ok=True)
    expected = {LEDGER_METADATA, REQUESTER_PUBLIC_KEY, RECEIPTS_DIR}
    if any(root.iterdir()):
        if {path.name for path in root.iterdir()} != expected:
            raise ValueError("acceptance ledger directory inventory is invalid")
        return root
    key_payload = _read_json_object(requester_public_key_file, label="requester public key")
    if "private_key_base64" in key_payload:
        raise ValueError("acceptance ledger must not embed requester private key material")
    identity = _requester_identity(requester_public_key_file)
    _write_json_atomic(
        root / LEDGER_METADATA,
        {"format": LEDGER_FORMAT, "requester": identity},
    )
    _write_json_atomic(root / REQUESTER_PUBLIC_KEY, key_payload)
    (root / RECEIPTS_DIR).mkdir(mode=0o755)
    return root


def verify_acceptance_ledger(
    ledger_dir: Path,
    *,
    requester_public_key_file: Path,
    minimum_checkpoint_file: Path | None = None,
    minimum_checkpoint_series_dir: Path | None = None,
    minimum_checkpoint_statement: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = ledger_dir.resolve()
    issues: list[str] = []
    entries: list[dict[str, Any]] = []
    if ledger_dir.is_symlink() or not root.is_dir():
        return {"format": VERIFIER_FORMAT, "passed": False, "issues": ["acceptance ledger is missing or invalid"], "entries": []}
    expected_top = {LEDGER_METADATA, REQUESTER_PUBLIC_KEY, RECEIPTS_DIR}
    actual_top = {path.name for path in root.iterdir()}
    if actual_top != expected_top:
        issues.append("acceptance ledger top-level inventory is invalid")
    try:
        pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
        embedded_key_id, embedded_public = load_public_key(root / REQUESTER_PUBLIC_KEY)
        metadata = _read_json_object(root / LEDGER_METADATA, label="acceptance ledger metadata")
        expected_identity = {
            "algorithm": ED25519_ALGORITHM,
            "key_id": pinned_key_id,
            "public_key_fingerprint": public_key_fingerprint(pinned_public),
        }
        if embedded_key_id != pinned_key_id or embedded_public != pinned_public:
            issues.append("embedded requester public key does not match the pinned key")
        if metadata.get("format") != LEDGER_FORMAT or metadata.get("requester") != expected_identity:
            issues.append("acceptance ledger metadata does not match the pinned requester")
        receipt_files = _receipt_files(root / RECEIPTS_DIR)
    except (OSError, ValueError) as exc:
        issues.append(str(exc))
        receipt_files = []
        pinned_public = ""
        expected_identity = {}

    previous_hash = ZERO_HASH
    seen_requests: dict[str, str] = {}
    receipt_hashes: list[str] = []
    for expected_sequence, path in enumerate(receipt_files, 1):
        try:
            envelope = _read_json_object(path, label="acceptance receipt envelope")
            statement = envelope.get("statement")
            signature = str(envelope.get("signature_base64") or "")
            if envelope.get("format") != ENVELOPE_FORMAT or not isinstance(statement, dict):
                raise ValueError("acceptance receipt envelope format is invalid")
            if statement.get("format") != RECEIPT_FORMAT:
                raise ValueError("acceptance receipt statement format is invalid")
            if statement.get("sequence") != expected_sequence:
                raise ValueError("acceptance receipt sequence is not contiguous")
            if statement.get("previous_receipt_sha256") != previous_hash:
                raise ValueError("acceptance receipt hash chain is invalid")
            if statement.get("requester") != expected_identity:
                raise ValueError("acceptance receipt requester identity is invalid")
            if not verify_ed25519(
                signature_base64=signature,
                public_key_base64=pinned_public,
                payload=_canonical(statement),
            ):
                raise ValueError("acceptance receipt signature is invalid")
            request_id = str(statement.get("request_id") or "")
            response_hash = str(statement.get("response_tree_sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{32}", request_id):
                raise ValueError("acceptance receipt request_id is invalid")
            if not re.fullmatch(r"[0-9a-f]{64}", response_hash):
                raise ValueError("acceptance receipt response identity is invalid")
            if request_id in seen_requests:
                raise ValueError("acceptance ledger contains a duplicate request_id")
            seen_requests[request_id] = response_hash
            previous_hash = _sha256(path)
            receipt_hashes.append(previous_hash)
            entries.append(statement)
        except (OSError, ValueError, TypeError) as exc:
            issues.append(f"{path.name}: {exc}")
            break
    supplied = sum(value is not None for value in (minimum_checkpoint_file, minimum_checkpoint_series_dir, minimum_checkpoint_statement))
    if supplied > 1:
        issues.append("only one minimum acceptance checkpoint source may be supplied")
    minimum_checkpoint: dict[str, Any] | None = minimum_checkpoint_statement
    if minimum_checkpoint_file is not None:
        checkpoint_report = verify_acceptance_checkpoint(minimum_checkpoint_file, requester_public_key_file=requester_public_key_file)
        if checkpoint_report.get("passed") is not True:
            issues.append("minimum acceptance checkpoint failed verification")
        else:
            minimum_checkpoint = checkpoint_report["statement"]
    if minimum_checkpoint_series_dir is not None:
        series_report = verify_acceptance_checkpoint_series(minimum_checkpoint_series_dir, requester_public_key_file=requester_public_key_file)
        if series_report.get("passed") is not True or not isinstance(series_report.get("latest_checkpoint"), dict):
            issues.append("minimum acceptance checkpoint series failed verification or is empty")
        else:
            minimum_checkpoint = series_report["latest_checkpoint"]
    if minimum_checkpoint is not None:
        checkpoint_count = int(minimum_checkpoint["receipt_count"])
        if len(entries) < checkpoint_count:
            issues.append("acceptance ledger is older than the minimum checkpoint")
        elif receipt_hashes[checkpoint_count - 1] != minimum_checkpoint["head_receipt_sha256"]:
            issues.append("acceptance ledger diverges from the minimum checkpoint")
        else:
            checkpoint_entry = entries[checkpoint_count - 1]
            if checkpoint_entry.get("request_id") != minimum_checkpoint["head_request_id"]:
                issues.append("acceptance ledger checkpoint request identity is inconsistent")
            if checkpoint_entry.get("response_tree_sha256") != minimum_checkpoint["head_response_tree_sha256"]:
                issues.append("acceptance ledger checkpoint response identity is inconsistent")
    return {
        "format": VERIFIER_FORMAT,
        "passed": not issues,
        "requester": expected_identity,
        "receipt_count": len(entries),
        "head_receipt_sha256": previous_hash,
        "accepted_requests": seen_requests,
        "entries": entries,
        "minimum_checkpoint": minimum_checkpoint,
        "issues": issues,
    }


def accept_response_bundle(
    *,
    response_dir: Path,
    expected_request_dir: Path,
    requester_private_key_file: Path,
    requester_public_key_file: Path,
    operator_public_key_file: Path,
    ledger_dir: Path,
    minimum_checkpoint_file: Path | None = None,
    minimum_checkpoint_series_dir: Path | None = None,
    source_root: Path | None = ROOT,
    now: datetime | None = None,
) -> dict[str, Any]:
    requester_key_id, requester_private, requester_public = load_private_key(requester_private_key_file)
    pinned_key_id, pinned_public = load_public_key(requester_public_key_file)
    if requester_key_id != pinned_key_id or requester_public != pinned_public:
        raise ValueError("requester private key does not match the pinned requester public key")
    response_report = verify_response_bundle(
        response_dir,
        expected_request_dir=expected_request_dir,
        requester_public_key_file=requester_public_key_file,
        operator_public_key_file=operator_public_key_file,
        source_root=source_root,
    )
    if response_report.get("integrity_passed") is not True:
        raise ValueError("external validation response failed integrity verification")
    request = verify_request_bundle(
        expected_request_dir,
        requester_public_key_file=requester_public_key_file,
        source_root=source_root,
        permit_expired_after_execution=_parse_response_created(response_dir),
    )
    root = initialize_ledger(ledger_dir, requester_public_key_file=requester_public_key_file)
    ledger_report = verify_acceptance_ledger(
        root,
        requester_public_key_file=requester_public_key_file,
        minimum_checkpoint_file=minimum_checkpoint_file,
        minimum_checkpoint_series_dir=minimum_checkpoint_series_dir,
    )
    if ledger_report.get("passed") is not True:
        raise ValueError("acceptance ledger failed integrity verification")
    response_identity = response_tree_identity(response_dir)
    request_id = str(request["request_id"])
    accepted = ledger_report["accepted_requests"]
    if request_id in accepted:
        if accepted[request_id] == response_identity["tree_sha256"]:
            raise ValueError("response replay: this request was already accepted")
        raise ValueError("operator equivocation: this request already has a different accepted response")
    response_statement = _read_json_object(response_dir / RESPONSE_JSON, label="response statement")
    operator_key_id, operator_public = load_public_key(operator_public_key_file)
    sequence = int(ledger_report["receipt_count"]) + 1
    accepted_at = (now or _utc_now()).astimezone(timezone.utc)
    statement = {
        "format": RECEIPT_FORMAT,
        "sequence": sequence,
        "previous_receipt_sha256": ledger_report["head_receipt_sha256"],
        "accepted_at": _iso(accepted_at),
        "request_id": request_id,
        "target_name": request["target_name"],
        "request_sha256": _sha256(expected_request_dir.resolve() / REQUEST_JSON),
        "request_signature_sha256": _sha256(expected_request_dir.resolve() / REQUEST_SIGNATURE),
        "response_tree_sha256": response_identity["tree_sha256"],
        "response_file_count": response_identity["file_count"],
        "response_statement_sha256": _sha256(response_dir.resolve() / RESPONSE_JSON),
        "response_signature_sha256": _sha256(response_dir.resolve() / RESPONSE_SIGNATURE),
        "operator_public_key_sha256": _sha256(response_dir.resolve() / OPERATOR_PUBLIC_KEY),
        "operator": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": operator_key_id,
            "public_key_fingerprint": public_key_fingerprint(operator_public),
        },
        "requester": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": requester_key_id,
            "public_key_fingerprint": public_key_fingerprint(requester_public),
        },
        "integrity_passed": True,
        "execution_source_attested": response_report.get("execution_source_attested") is True,
        "validation_passed": response_report.get("validation_passed") is True,
        "validation_complete": response_report.get("validation_complete") is True,
        "validation_status_counts": response_statement.get("validation_status_counts"),
    }
    signature = sign_ed25519(requester_private, _canonical(statement))
    envelope = {"format": ENVELOPE_FORMAT, "statement": statement, "signature_base64": signature}
    final_path = root / RECEIPTS_DIR / f"{sequence:08d}.receipt.json"
    _publish_exclusive(final_path, envelope)
    final_report = verify_acceptance_ledger(
        root,
        requester_public_key_file=requester_public_key_file,
        minimum_checkpoint_file=minimum_checkpoint_file,
        minimum_checkpoint_series_dir=minimum_checkpoint_series_dir,
    )
    if final_report.get("passed") is not True or final_report.get("receipt_count") != sequence:
        raise RuntimeError("published acceptance receipt failed ledger verification")
    return {
        "accepted": True,
        "receipt_file": str(final_path),
        "receipt_sha256": _sha256(final_path),
        "statement": statement,
        "ledger": {
            "receipt_count": final_report["receipt_count"],
            "head_receipt_sha256": final_report["head_receipt_sha256"],
        },
    }


def _parse_response_created(response_dir: Path) -> datetime:
    statement = _read_json_object(response_dir.resolve() / RESPONSE_JSON, label="response statement")
    text = str(statement.get("created_at") or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("response created_at is invalid") from exc
    if value.tzinfo is None:
        raise ValueError("response created_at must include a timezone")
    return value.astimezone(timezone.utc)


def _render(payload: dict[str, Any], output: Path | None = None) -> None:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    print(text, end="")
    if output is not None:
        _write_json_atomic(output, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    accept = sub.add_parser("accept-response")
    accept.add_argument("--response-dir", type=Path, required=True)
    accept.add_argument("--expected-request-dir", type=Path, required=True)
    accept.add_argument("--requester-private-key-file", type=Path, required=True)
    accept.add_argument("--requester-public-key-file", type=Path, required=True)
    accept.add_argument("--operator-public-key-file", type=Path, required=True)
    accept.add_argument("--ledger-dir", type=Path, required=True)
    accept.add_argument("--minimum-checkpoint-file", type=Path)
    accept.add_argument("--minimum-checkpoint-series-dir", type=Path)
    accept.add_argument("--without-source-tree-binding", action="store_true")
    accept.add_argument("--json-output", type=Path)

    verify = sub.add_parser("verify-ledger")
    verify.add_argument("ledger_dir", type=Path)
    verify.add_argument("--requester-public-key-file", type=Path, required=True)
    verify.add_argument("--minimum-checkpoint-file", type=Path)
    verify.add_argument("--minimum-checkpoint-series-dir", type=Path)
    verify.add_argument("--json-output", type=Path)

    checkpoint = sub.add_parser("create-checkpoint")
    checkpoint.add_argument("ledger_dir", type=Path)
    checkpoint.add_argument("--requester-private-key-file", type=Path, required=True)
    checkpoint.add_argument("--requester-public-key-file", type=Path, required=True)
    checkpoint.add_argument("--output-file", type=Path, required=True)
    checkpoint.add_argument("--json-output", type=Path)

    verify_checkpoint = sub.add_parser("verify-checkpoint")
    verify_checkpoint.add_argument("checkpoint_file", type=Path)
    verify_checkpoint.add_argument("--requester-public-key-file", type=Path, required=True)
    verify_checkpoint.add_argument("--json-output", type=Path)


    append_series = sub.add_parser("append-checkpoint-series")
    append_series.add_argument("ledger_dir", type=Path)
    append_series.add_argument("--series-dir", type=Path, required=True)
    append_series.add_argument("--requester-private-key-file", type=Path, required=True)
    append_series.add_argument("--requester-public-key-file", type=Path, required=True)
    append_series.add_argument("--json-output", type=Path)

    verify_series = sub.add_parser("verify-checkpoint-series")
    verify_series.add_argument("series_dir", type=Path)
    verify_series.add_argument("--requester-public-key-file", type=Path, required=True)
    verify_series.add_argument("--json-output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "accept-response":
            report = accept_response_bundle(
                response_dir=args.response_dir,
                expected_request_dir=args.expected_request_dir,
                requester_private_key_file=args.requester_private_key_file,
                requester_public_key_file=args.requester_public_key_file,
                operator_public_key_file=args.operator_public_key_file,
                ledger_dir=args.ledger_dir,
                minimum_checkpoint_file=args.minimum_checkpoint_file,
                minimum_checkpoint_series_dir=args.minimum_checkpoint_series_dir,
                source_root=None if args.without_source_tree_binding else ROOT,
            )
            _render(report, args.json_output)
            return 0
        if args.command == "verify-ledger":
            report = verify_acceptance_ledger(
                args.ledger_dir,
                requester_public_key_file=args.requester_public_key_file,
                minimum_checkpoint_file=args.minimum_checkpoint_file,
                minimum_checkpoint_series_dir=args.minimum_checkpoint_series_dir,
            )
            _render(report, args.json_output)
            return 0 if report["passed"] else 1
        if args.command == "create-checkpoint":
            report = create_acceptance_checkpoint(
                args.ledger_dir,
                requester_private_key_file=args.requester_private_key_file,
                requester_public_key_file=args.requester_public_key_file,
                output_file=args.output_file,
            )
            _render(report, args.json_output)
            return 0
        if args.command == "verify-checkpoint":
            report = verify_acceptance_checkpoint(
                args.checkpoint_file,
                requester_public_key_file=args.requester_public_key_file,
            )
            _render(report, args.json_output)
            return 0 if report["passed"] else 1
        if args.command == "append-checkpoint-series":
            report = append_acceptance_checkpoint_series(
                args.ledger_dir,
                series_dir=args.series_dir,
                requester_private_key_file=args.requester_private_key_file,
                requester_public_key_file=args.requester_public_key_file,
            )
            _render(report, args.json_output)
            return 0
        if args.command == "verify-checkpoint-series":
            report = verify_acceptance_checkpoint_series(
                args.series_dir,
                requester_public_key_file=args.requester_public_key_file,
            )
            _render(report, args.json_output)
            return 0 if report["passed"] else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"external validation acceptance failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
