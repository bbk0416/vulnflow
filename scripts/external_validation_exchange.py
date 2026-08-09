from __future__ import annotations

"""Signed challenge-response exchange for detached external validation evidence.

The requester signs an expiring challenge bound to an exact VulnFlow public
source manifest.  A runner verifies that challenge against a pinned requester
public key before executing the existing external-validation gate.  The runner
then signs a response statement binding the original challenge to every byte of
the returned evidence directory.  A verifier requires its own retained copy of
the request plus pinned requester and runner public keys, so replacing the whole
unsigned evidence directory can no longer manufacture authenticity.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.public_signing import (
    ED25519_ALGORITHM,
    b64encode_raw,
    public_key_fingerprint,
    public_key_from_private,
    sign_ed25519,
    verify_ed25519,
)
from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from app.core.signing import KEY_ID_RE
from scripts.external_validation_gate import REQUIRED_CHECKS, REQUEST_BINDING_FORMAT
from scripts.external_validation_source_attestation import (
    FORMAT as SOURCE_ATTESTATION_FORMAT,
    attest_public_source,
    copy_verified_public_source,
    require_public_source,
)
from scripts.verify_external_validation_evidence import verify_evidence_directory

REQUEST_FORMAT = "vulnflow-external-validation-request/2"
RESPONSE_FORMAT = "vulnflow-external-validation-response/4"
KEY_FORMAT = "vulnflow-external-validation-ed25519-key/1"
VERIFIER_FORMAT = "vulnflow-external-validation-response-verifier/1"
PAYLOAD_MANIFEST = "PAYLOAD_SHA256SUMS.txt"
REQUEST_JSON = "request.json"
REQUEST_SIGNATURE = "request.ed25519"
RESPONSE_JSON = "response-statement.json"
RESPONSE_SIGNATURE = "response.ed25519"
OPERATOR_PUBLIC_KEY = "operator-public-key.json"
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RUNNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@/-]{0,127}$")
MANIFEST_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")
MAX_REQUEST_LIFETIME_SECONDS = 7 * 24 * 60 * 60
MIN_REQUEST_LIFETIME_SECONDS = 5 * 60


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_json(path: Path, payload: dict[str, Any], *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if private and os.name == "posix":
        path.chmod(0o600)


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or not payload:
        raise ValueError(f"{label} must be a non-empty JSON object")
    return payload


def _read_text(path: Path, *, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{label} must be ASCII text") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def evidence_request_binding(request_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    directory = request_dir.resolve()
    return {
        "format": REQUEST_BINDING_FORMAT,
        "request_id": request["request_id"],
        "challenge_nonce_sha256": _sha256_text(str(request["challenge_nonce"])),
        "target_name": request["target_name"],
        "request_sha256": _sha256(directory / REQUEST_JSON),
        "request_signature_sha256": _sha256(directory / REQUEST_SIGNATURE),
        "request_created_at": request["created_at"],
        "request_expires_at": request["expires_at"],
        "source_identity": request["source_identity"],
        "authorized_operator": request["authorized_operator"],
    }


def _evidence_collection_binding(
    aggregate: dict[str, Any],
    *,
    expected_binding: dict[str, Any],
    response_created: datetime,
) -> tuple[dict[str, Any], datetime, datetime]:
    binding = aggregate.get("request_binding")
    if binding != expected_binding:
        raise ValueError("external validation evidence is not bound to this signed request")
    window = aggregate.get("collection_window")
    if not isinstance(window, dict):
        raise ValueError("external validation evidence has no collection window")
    started = _parse_time(window.get("started_at"), label="evidence collection started_at")
    completed = _parse_time(window.get("completed_at"), label="evidence collection completed_at")
    request_created = _parse_time(expected_binding.get("request_created_at"), label="request created_at")
    request_expires = _parse_time(expected_binding.get("request_expires_at"), label="request expires_at")
    if started > completed:
        raise ValueError("external validation evidence collection window is reversed")
    if started < request_created - timedelta(minutes=5):
        raise ValueError("external validation evidence predates the signed request")
    if completed > request_expires:
        raise ValueError("external validation evidence completed after request expiry")
    if completed > response_created:
        raise ValueError("external validation evidence completed after response creation")
    return binding, started, completed


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, *, label: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _source_identity(root: Path = ROOT) -> dict[str, Any]:
    version_path = root / "VERSION"
    manifest_path = root / "SHA256SUMS.txt"
    if not version_path.is_file() or not manifest_path.is_file():
        raise ValueError("source tree must contain VERSION and SHA256SUMS.txt")
    return {
        "version": version_path.read_text(encoding="utf-8").strip(),
        "schema_version": CURRENT_SCHEMA_VERSION,
        "public_manifest_sha256": _sha256(manifest_path),
    }


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in value
        and value not in {".", ""}
    )


def _require_empty_output(path: Path, *, label: str) -> Path:
    raw = path.expanduser()
    if raw.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = raw.resolve()
    filesystem_root = Path(resolved.anchor)
    if resolved in {filesystem_root, ROOT} or resolved in ROOT.parents:
        raise ValueError(f"unsafe {label}: {resolved}")
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"{label} must be a directory path: {resolved}")
    if resolved.exists() and any(resolved.iterdir()):
        raise ValueError(f"{label} must be absent or empty: {resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _paths_overlap(first: Path, second: Path) -> bool:
    left = first.resolve()
    right = second.resolve()
    return left == right or left in right.parents or right in left.parents


def _validate_key_payload(payload: dict[str, Any], *, require_private: bool) -> tuple[str, str, str]:
    if payload.get("format") != KEY_FORMAT:
        raise ValueError("key file has the wrong format")
    key_id = str(payload.get("key_id") or "").strip()
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("key file contains an invalid key_id")
    public_key = str(payload.get("public_key_base64") or "").strip()
    fingerprint = public_key_fingerprint(public_key)
    if payload.get("public_key_fingerprint") != fingerprint:
        raise ValueError("key file public-key fingerprint does not match")
    private_key = str(payload.get("private_key_base64") or "").strip()
    if require_private:
        if not private_key:
            raise ValueError("private key file has no private key")
        if public_key_from_private(private_key) != public_key:
            raise ValueError("private and public key material do not match")
    elif private_key:
        raise ValueError("public key file must not contain private key material")
    return key_id, private_key, public_key


def load_private_key(path: Path) -> tuple[str, str, str]:
    payload = _read_json_object(path, label="private key file")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise ValueError("private key file permissions must not allow group or other access")
    return _validate_key_payload(payload, require_private=True)


def load_public_key(path: Path) -> tuple[str, str]:
    payload = _read_json_object(path, label="public key file")
    key_id, _, public_key = _validate_key_payload(payload, require_private=False)
    return key_id, public_key


def generate_keypair(*, key_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not KEY_ID_RE.fullmatch(str(key_id or "")):
        raise ValueError("invalid Ed25519 key_id")
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
    private_b64 = b64encode_raw(private_raw)
    public_b64 = b64encode_raw(public_raw)
    common = {
        "format": KEY_FORMAT,
        "algorithm": ED25519_ALGORITHM,
        "key_id": key_id,
        "public_key_base64": public_b64,
        "public_key_fingerprint": public_key_fingerprint(public_b64),
    }
    return ({**common, "private_key_base64": private_b64}, dict(common))


def create_request_bundle(
    *,
    output_dir: Path,
    private_key_file: Path,
    operator_public_key_file: Path,
    target_name: str,
    lifetime_seconds: int,
    minimum_scanner_files: int = 20,
    soak_iterations: int = 12,
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    if not TARGET_RE.fullmatch(str(target_name or "")):
        raise ValueError("target_name must use 1-64 letters, digits, dot, underscore, or hyphen")
    if not MIN_REQUEST_LIFETIME_SECONDS <= lifetime_seconds <= MAX_REQUEST_LIFETIME_SECONDS:
        raise ValueError("request lifetime must be between 300 and 604800 seconds")
    if minimum_scanner_files < 1 or soak_iterations < 2:
        raise ValueError("minimum_scanner_files must be >=1 and soak_iterations >=2")
    key_id, private_key, public_key = load_private_key(private_key_file)
    operator_key_id, operator_public_key = load_public_key(operator_public_key_file)
    created = (now or _utc_now()).astimezone(timezone.utc)
    expires = created + timedelta(seconds=lifetime_seconds)
    request_id = secrets.token_hex(16)
    challenge_nonce = nonce or secrets.token_urlsafe(32)
    if len(challenge_nonce) < 32 or len(challenge_nonce) > 256:
        raise ValueError("nonce must contain between 32 and 256 characters")
    statement = {
        "format": REQUEST_FORMAT,
        "request_id": request_id,
        "challenge_nonce": challenge_nonce,
        "created_at": _iso(created),
        "expires_at": _iso(expires),
        "target_name": target_name,
        "source_identity": _source_identity(),
        "required_checks": list(REQUIRED_CHECKS),
        "parameters": {
            "minimum_scanner_files": minimum_scanner_files,
            "soak_iterations": soak_iterations,
        },
        "requester": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": key_id,
            "public_key_fingerprint": public_key_fingerprint(public_key),
        },
        "authorized_operator": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": operator_key_id,
            "public_key_fingerprint": public_key_fingerprint(operator_public_key),
        },
    }
    signature = sign_ed25519(private_key, _canonical(statement))
    output = _require_empty_output(output_dir, label="request output directory")
    _write_json(output / REQUEST_JSON, statement)
    (output / REQUEST_SIGNATURE).write_text(signature + "\n", encoding="ascii")
    return statement


def verify_request_bundle(
    request_dir: Path,
    *,
    requester_public_key_file: Path,
    source_root: Path | None = ROOT,
    now: datetime | None = None,
    permit_expired_after_execution: datetime | None = None,
) -> dict[str, Any]:
    directory = request_dir.resolve()
    if request_dir.is_symlink() or not directory.is_dir():
        raise ValueError("request bundle must be a regular directory")
    actual_names = {path.name for path in directory.iterdir()}
    if actual_names != {REQUEST_JSON, REQUEST_SIGNATURE}:
        raise ValueError("request bundle must contain exactly request.json and request.ed25519")
    statement = _read_json_object(directory / REQUEST_JSON, label="request statement")
    signature = _read_text(directory / REQUEST_SIGNATURE, label="request signature")
    key_id, public_key = load_public_key(requester_public_key_file)
    if statement.get("format") != REQUEST_FORMAT:
        raise ValueError("request statement has the wrong format")
    requester = statement.get("requester")
    if not isinstance(requester, dict):
        raise ValueError("request statement has no requester identity")
    if requester.get("algorithm") != ED25519_ALGORITHM:
        raise ValueError("request statement uses an unsupported signature algorithm")
    if requester.get("key_id") != key_id:
        raise ValueError("request key_id does not match the pinned requester key")
    if requester.get("public_key_fingerprint") != public_key_fingerprint(public_key):
        raise ValueError("request fingerprint does not match the pinned requester key")
    authorized_operator = statement.get("authorized_operator")
    if not isinstance(authorized_operator, dict):
        raise ValueError("request statement has no authorized operator identity")
    if authorized_operator.get("algorithm") != ED25519_ALGORITHM:
        raise ValueError("request authorized operator uses an unsupported signature algorithm")
    operator_key_id = str(authorized_operator.get("key_id") or "")
    operator_fingerprint = str(authorized_operator.get("public_key_fingerprint") or "")
    if not KEY_ID_RE.fullmatch(operator_key_id):
        raise ValueError("request authorized operator key_id is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", operator_fingerprint):
        raise ValueError("request authorized operator fingerprint is invalid")
    if not verify_ed25519(
        signature_base64=signature,
        public_key_base64=public_key,
        payload=_canonical(statement),
    ):
        raise ValueError("request signature is invalid")
    request_id = str(statement.get("request_id") or "")
    nonce = str(statement.get("challenge_nonce") or "")
    target_name = str(statement.get("target_name") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ValueError("request_id is invalid")
    if len(nonce) < 32 or len(nonce) > 256:
        raise ValueError("challenge nonce is invalid")
    if not TARGET_RE.fullmatch(target_name):
        raise ValueError("request target_name is invalid")
    created = _parse_time(statement.get("created_at"), label="request created_at")
    expires = _parse_time(statement.get("expires_at"), label="request expires_at")
    lifetime = (expires - created).total_seconds()
    if not MIN_REQUEST_LIFETIME_SECONDS <= lifetime <= MAX_REQUEST_LIFETIME_SECONDS:
        raise ValueError("request lifetime is outside the supported range")
    effective_now = (now or _utc_now()).astimezone(timezone.utc)
    expiry_reference = permit_expired_after_execution or effective_now
    if expiry_reference < created - timedelta(minutes=5):
        raise ValueError("request is not yet valid")
    if expiry_reference > expires:
        raise ValueError("request has expired")
    if statement.get("required_checks") != list(REQUIRED_CHECKS):
        raise ValueError("request required_checks do not match this release")
    parameters = statement.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("request parameters are missing")
    if int(parameters.get("minimum_scanner_files") or 0) < 1:
        raise ValueError("request minimum_scanner_files is invalid")
    if int(parameters.get("soak_iterations") or 0) < 2:
        raise ValueError("request soak_iterations is invalid")
    if source_root is not None:
        source_report = require_public_source(source_root)
        if statement.get("source_identity") != _source_identity(source_root):
            raise ValueError("request source identity does not match the local source tree")
        statement = dict(statement)
        statement["verified_source_attestation"] = source_report["identity"]
    return statement


def _manifest_lines(root: Path, relative_roots: Iterable[str]) -> list[str]:
    lines: list[str] = []
    for relative_root in relative_roots:
        base = root / relative_root
        if base.is_symlink():
            raise ValueError(f"response payload contains a symbolic link: {relative_root}")
        if base.is_file():
            lines.append(f"{_sha256(base)}  {relative_root}")
            continue
        if not base.is_dir():
            raise ValueError(f"response payload path is missing: {relative_root}")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"response payload contains a symbolic link: {path}")
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                lines.append(f"{_sha256(path)}  {relative}")
    return sorted(lines)


def _load_payload_manifest(path: Path) -> tuple[dict[str, str], list[str]]:
    issues: list[str] = []
    entries: dict[str, str] = {}
    if path.is_symlink() or not path.is_file():
        return {}, ["payload manifest is missing or not a regular file"]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}, ["payload manifest is not valid UTF-8"]
    for number, line in enumerate(lines, 1):
        match = MANIFEST_RE.fullmatch(line)
        if not match:
            issues.append(f"invalid payload manifest line {number}")
            continue
        digest, relative = match.groups()
        if not _safe_relative(relative):
            issues.append(f"unsafe payload path at line {number}")
            continue
        if relative in entries:
            issues.append(f"duplicate payload path: {relative}")
            continue
        entries[relative] = digest
    return entries, issues


def sign_response_bundle(
    *,
    request_dir: Path,
    requester_public_key_file: Path,
    evidence_dir: Path,
    operator_private_key_file: Path,
    output_dir: Path,
    runner_label: str,
    now: datetime | None = None,
    source_attestation_before: dict[str, Any] | None = None,
    source_attestation_after: dict[str, Any] | None = None,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    if not RUNNER_RE.fullmatch(str(runner_label or "")):
        raise ValueError("runner_label contains unsupported characters or length")
    created = (now or _utc_now()).astimezone(timezone.utc)
    request = verify_request_bundle(
        request_dir,
        requester_public_key_file=requester_public_key_file,
        source_root=source_root,
        now=created,
    )
    if source_attestation_before is None or source_attestation_after is None:
        current_source = require_public_source(source_root)
        source_attestation_before = current_source
        source_attestation_after = current_source
        source_attestation_mode = "detached-signing-current-source"
    else:
        source_attestation_mode = "execute-request-pre-post"
    for label, report in (("before", source_attestation_before), ("after", source_attestation_after)):
        if not isinstance(report, dict) or report.get("format") != SOURCE_ATTESTATION_FORMAT or report.get("passed") is not True:
            raise ValueError(f"source attestation {label} is missing or invalid")
        if not isinstance(report.get("identity"), dict):
            raise ValueError(f"source attestation {label} has no identity")
    if source_attestation_before["identity"] != source_attestation_after["identity"]:
        raise ValueError("source identity changed during external validation execution")
    if source_attestation_before["identity"] != require_public_source(source_root)["identity"]:
        raise ValueError("source attestation does not match the signing source tree")
    evidence = evidence_dir.resolve()
    request_resolved = request_dir.resolve()
    output_resolved = output_dir.expanduser().resolve()
    if _paths_overlap(output_resolved, evidence) or _paths_overlap(output_resolved, request_resolved):
        raise ValueError("response output directory must not overlap request or evidence input")
    if _paths_overlap(request_resolved, evidence):
        raise ValueError("request and evidence directories must not overlap")
    evidence_verification = verify_evidence_directory(evidence, source_root=source_root)
    if not evidence_verification.get("passed"):
        raise ValueError("external validation evidence failed independent integrity verification")
    aggregate = _read_json_object(
        evidence / "external-validation-report.json",
        label="external validation aggregate",
    )
    expected_evidence_binding = evidence_request_binding(request_dir, request)
    evidence_binding, collection_started, collection_completed = _evidence_collection_binding(
        aggregate,
        expected_binding=expected_evidence_binding,
        response_created=created,
    )
    operator_key_id, operator_private, operator_public = load_private_key(operator_private_key_file)
    authorized_operator = request["authorized_operator"]
    if (
        authorized_operator.get("key_id") != operator_key_id
        or authorized_operator.get("public_key_fingerprint") != public_key_fingerprint(operator_public)
    ):
        raise ValueError("operator private key is not authorized by the signed request")
    output = _require_empty_output(output_dir, label="response output directory")
    shutil.copytree(request_dir.resolve(), output / "request", symlinks=False)
    shutil.copytree(evidence, output / "evidence", symlinks=False)
    public_payload = {
        "format": KEY_FORMAT,
        "algorithm": ED25519_ALGORITHM,
        "key_id": operator_key_id,
        "public_key_base64": operator_public,
        "public_key_fingerprint": public_key_fingerprint(operator_public),
    }
    _write_json(output / OPERATOR_PUBLIC_KEY, public_payload)
    lines = _manifest_lines(output, ["request", "evidence", OPERATOR_PUBLIC_KEY])
    (output / PAYLOAD_MANIFEST).write_text("\n".join(lines) + "\n", encoding="utf-8")
    request_json = output / "request" / REQUEST_JSON
    request_signature = output / "request" / REQUEST_SIGNATURE
    evidence_report = output / "evidence" / "external-validation-report.json"
    evidence_manifest = output / "evidence" / "SHA256SUMS.txt"
    statement = {
        "format": RESPONSE_FORMAT,
        "created_at": _iso(created),
        "request_id": request["request_id"],
        "challenge_nonce": request["challenge_nonce"],
        "target_name": request["target_name"],
        "request_sha256": _sha256(request_json),
        "request_signature_sha256": _sha256(request_signature),
        "request_source_identity": request["source_identity"],
        "response_source_identity": _source_identity(source_root),
        "authorized_operator": request["authorized_operator"],
        "payload_manifest_sha256": _sha256(output / PAYLOAD_MANIFEST),
        "evidence_report_sha256": _sha256(evidence_report),
        "evidence_manifest_sha256": _sha256(evidence_manifest),
        "evidence_request_binding_sha256": hashlib.sha256(_canonical(evidence_binding)).hexdigest(),
        "evidence_collection_window": {
            "started_at": _iso(collection_started),
            "completed_at": _iso(collection_completed),
        },
        "validation_passed": aggregate.get("passed") is True,
        "validation_complete": aggregate.get("complete") is True,
        "validation_status_counts": aggregate.get("status_counts"),
        "source_attestation": {
            "format": SOURCE_ATTESTATION_FORMAT,
            "mode": source_attestation_mode,
            "before": source_attestation_before["identity"],
            "after": source_attestation_after["identity"],
        },
        "runner": {
            "label": runner_label,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "operator": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": operator_key_id,
            "public_key_fingerprint": public_key_fingerprint(operator_public),
        },
    }
    _write_json(output / RESPONSE_JSON, statement)
    signature = sign_ed25519(operator_private, _canonical(statement))
    (output / RESPONSE_SIGNATURE).write_text(signature + "\n", encoding="ascii")
    return statement


def verify_response_bundle(
    response_dir: Path,
    *,
    expected_request_dir: Path,
    requester_public_key_file: Path,
    operator_public_key_file: Path,
    source_root: Path | None = ROOT,
) -> dict[str, Any]:
    directory = response_dir.resolve()
    issues: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": "" if passed else detail})
        if not passed:
            issues.append(detail)

    if response_dir.is_symlink() or not directory.is_dir():
        return {
            "format": VERIFIER_FORMAT,
            "integrity_passed": False,
            "validation_passed": False,
            "checks": [],
            "issues": ["response bundle is missing, not a directory, or a symbolic link"],
        }

    symlinks = [path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_symlink()]
    check("no_symbolic_links", not symlinks, "response bundle contains symbolic links")
    fixed = {PAYLOAD_MANIFEST, RESPONSE_JSON, RESPONSE_SIGNATURE}
    expected_top = {"request", "evidence", OPERATOR_PUBLIC_KEY, *fixed}
    actual_top = {path.name for path in directory.iterdir()}
    check("top_level_inventory", actual_top == expected_top, "response top-level inventory is unexpected")

    try:
        expected_request = verify_request_bundle(
            expected_request_dir,
            requester_public_key_file=requester_public_key_file,
            source_root=source_root,
            permit_expired_after_execution=_parse_time(
                _read_json_object(directory / RESPONSE_JSON, label="response statement").get("created_at"),
                label="response created_at",
            ),
        )
        embedded_request = verify_request_bundle(
            directory / "request",
            requester_public_key_file=requester_public_key_file,
            source_root=source_root,
            permit_expired_after_execution=_parse_time(
                _read_json_object(directory / RESPONSE_JSON, label="response statement").get("created_at"),
                label="response created_at",
            ),
        )
        request_ok = (
            _sha256(expected_request_dir.resolve() / REQUEST_JSON)
            == _sha256(directory / "request" / REQUEST_JSON)
            and _sha256(expected_request_dir.resolve() / REQUEST_SIGNATURE)
            == _sha256(directory / "request" / REQUEST_SIGNATURE)
            and expected_request == embedded_request
        )
    except (OSError, ValueError) as exc:
        expected_request = {}
        embedded_request = {}
        request_ok = False
        issues.append(f"request verification failed: {exc}")
    check("expected_request_binding", request_ok, "embedded request does not match the retained expected request")

    entries, manifest_issues = _load_payload_manifest(directory / PAYLOAD_MANIFEST)
    if manifest_issues:
        issues.extend(manifest_issues)
    actual_payload: dict[str, Path] = {}
    for relative_root in ("request", "evidence"):
        base = directory / relative_root
        if base.is_dir():
            for path in base.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    actual_payload[path.relative_to(directory).as_posix()] = path
    operator_embedded = directory / OPERATOR_PUBLIC_KEY
    if operator_embedded.is_file() and not operator_embedded.is_symlink():
        actual_payload[OPERATOR_PUBLIC_KEY] = operator_embedded
    missing = sorted(set(entries) - set(actual_payload))
    unlisted = sorted(set(actual_payload) - set(entries))
    check("payload_inventory", not missing and not unlisted and not manifest_issues, "payload manifest inventory mismatch")
    mismatched = sorted(
        relative for relative, digest in entries.items()
        if relative in actual_payload and _sha256(actual_payload[relative]) != digest
    )
    check("payload_hashes", not mismatched and not manifest_issues, "payload manifest hash mismatch")

    try:
        statement = _read_json_object(directory / RESPONSE_JSON, label="response statement")
        signature = _read_text(directory / RESPONSE_SIGNATURE, label="response signature")
        operator_key_id, operator_public = load_public_key(operator_public_key_file)
        embedded_operator_id, embedded_operator_public = load_public_key(operator_embedded)
        operator_statement = statement.get("operator")
        authorized_operator = embedded_request.get("authorized_operator") if isinstance(embedded_request, dict) else None
        operator_identity_ok = (
            isinstance(operator_statement, dict)
            and isinstance(authorized_operator, dict)
            and embedded_operator_id == operator_key_id
            and embedded_operator_public == operator_public
            and operator_statement.get("algorithm") == ED25519_ALGORITHM
            and operator_statement.get("key_id") == operator_key_id
            and operator_statement.get("public_key_fingerprint")
            == public_key_fingerprint(operator_public)
            and authorized_operator.get("algorithm") == ED25519_ALGORITHM
            and authorized_operator.get("key_id") == operator_key_id
            and authorized_operator.get("public_key_fingerprint")
            == public_key_fingerprint(operator_public)
            and statement.get("authorized_operator") == authorized_operator
        )
        signature_ok = verify_ed25519(
            signature_base64=signature,
            public_key_base64=operator_public,
            payload=_canonical(statement),
        )
    except (OSError, ValueError, TypeError) as exc:
        statement = {}
        operator_identity_ok = False
        signature_ok = False
        issues.append(f"response signature verification failed: {exc}")
    check("operator_identity", operator_identity_ok, "operator identity does not match the pinned public key")
    check("response_signature", signature_ok, "response Ed25519 signature is invalid")

    evidence_report_path = directory / "evidence" / "external-validation-report.json"
    evidence_manifest_path = directory / "evidence" / "SHA256SUMS.txt"
    try:
        aggregate = _read_json_object(evidence_report_path, label="external validation aggregate")
        evidence_verification = verify_evidence_directory(
            directory / "evidence",
            source_root=source_root,
        )
        evidence_ok = evidence_verification.get("passed") is True
    except (OSError, ValueError) as exc:
        aggregate = {}
        evidence_verification = {"passed": False, "issues": [str(exc)]}
        evidence_ok = False
    check("evidence_integrity", evidence_ok, "embedded evidence failed independent verification")

    try:
        current_source_attestation = require_public_source(source_root) if source_root is not None else None
    except (OSError, ValueError) as exc:
        current_source_attestation = None
        issues.append(f"source attestation verification failed: {exc}")
    statement_source = statement.get("source_attestation") if isinstance(statement, dict) else None
    source_attestation_ok = (
        isinstance(statement_source, dict)
        and statement_source.get("format") == SOURCE_ATTESTATION_FORMAT
        and statement_source.get("mode") in {"execute-request-pre-post", "detached-signing-current-source"}
        and isinstance(statement_source.get("before"), dict)
        and statement_source.get("before") == statement_source.get("after")
        and (current_source_attestation is None or statement_source.get("before") == current_source_attestation.get("identity"))
    )
    execution_source_attested = bool(source_attestation_ok and statement_source.get("mode") == "execute-request-pre-post")
    check("source_execution_attestation", source_attestation_ok, "response source attestation is missing, changed, or does not match the verified source tree")

    response_created_ok = False
    response_bindings_ok = False
    evidence_request_binding_ok = False
    evidence_collection_window_ok = False
    if statement and embedded_request:
        try:
            response_created = _parse_time(statement.get("created_at"), label="response created_at")
            request_created = _parse_time(embedded_request.get("created_at"), label="request created_at")
            request_expires = _parse_time(embedded_request.get("expires_at"), label="request expires_at")
            response_created_ok = request_created - timedelta(minutes=5) <= response_created <= request_expires
            expected_evidence_binding = evidence_request_binding(directory / "request", embedded_request)
            actual_binding, collection_started, collection_completed = _evidence_collection_binding(
                aggregate,
                expected_binding=expected_evidence_binding,
                response_created=response_created,
            )
            evidence_request_binding_ok = True
            statement_window = statement.get("evidence_collection_window")
            evidence_collection_window_ok = (
                isinstance(statement_window, dict)
                and statement_window.get("started_at") == _iso(collection_started)
                and statement_window.get("completed_at") == _iso(collection_completed)
                and statement.get("evidence_request_binding_sha256")
                == hashlib.sha256(_canonical(actual_binding)).hexdigest()
            )
        except (OSError, ValueError, KeyError):
            response_created_ok = False
            evidence_request_binding_ok = False
            evidence_collection_window_ok = False
        response_bindings_ok = (
            statement.get("format") == RESPONSE_FORMAT
            and statement.get("request_id") == embedded_request.get("request_id")
            and statement.get("challenge_nonce") == embedded_request.get("challenge_nonce")
            and statement.get("target_name") == embedded_request.get("target_name")
            and statement.get("request_sha256") == _sha256(directory / "request" / REQUEST_JSON)
            and statement.get("request_signature_sha256") == _sha256(directory / "request" / REQUEST_SIGNATURE)
            and statement.get("request_source_identity") == embedded_request.get("source_identity")
            and statement.get("response_source_identity") == embedded_request.get("source_identity")
            and statement.get("authorized_operator") == embedded_request.get("authorized_operator")
            and statement.get("payload_manifest_sha256") == _sha256(directory / PAYLOAD_MANIFEST)
            and statement.get("evidence_report_sha256") == _sha256(evidence_report_path)
            and statement.get("evidence_manifest_sha256") == _sha256(evidence_manifest_path)
            and statement.get("validation_passed") is (aggregate.get("passed") is True)
            and statement.get("validation_complete") is (aggregate.get("complete") is True)
            and statement.get("validation_status_counts") == aggregate.get("status_counts")
            and evidence_request_binding_ok
            and evidence_collection_window_ok
            and source_attestation_ok
        )
    check("response_time_window", response_created_ok, "response was not created inside the signed request window")
    check("evidence_request_binding", evidence_request_binding_ok, "evidence was not collected for the retained signed request")
    check("evidence_collection_window", evidence_collection_window_ok, "evidence collection timing is missing or inconsistent")
    check("challenge_response_binding", response_bindings_ok, "response statement does not bind the request and evidence exactly")

    integrity_passed = bool(checks) and all(item["passed"] for item in checks)
    return {
        "format": VERIFIER_FORMAT,
        "integrity_passed": integrity_passed,
        "execution_source_attested": execution_source_attested,
        "validation_passed": bool(integrity_passed and execution_source_attested and statement.get("validation_passed") is True),
        "validation_complete": bool(integrity_passed and execution_source_attested and statement.get("validation_complete") is True),
        "request_id": str(statement.get("request_id") or ""),
        "target_name": str(statement.get("target_name") or ""),
        "operator_key_id": str(statement.get("operator", {}).get("key_id") or "") if isinstance(statement.get("operator"), dict) else "",
        "checks": checks,
        "issues": list(dict.fromkeys(issue for issue in issues if issue)),
        "evidence_verification": evidence_verification,
    }


def execute_request(
    *,
    request_dir: Path,
    requester_public_key_file: Path,
    operator_private_key_file: Path,
    output_dir: Path,
    evidence_output_dir: Path,
    runner_label: str,
    scanner_dir: Path | None,
    chromium: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    if _paths_overlap(output_dir, evidence_output_dir):
        raise ValueError("response and evidence output directories must not overlap")
    if _paths_overlap(request_dir, output_dir) or _paths_overlap(request_dir, evidence_output_dir):
        raise ValueError("execution outputs must not overlap the request bundle")
    require_public_source(ROOT)
    request = verify_request_bundle(
        request_dir,
        requester_public_key_file=requester_public_key_file,
        source_root=ROOT,
    )
    parameters = request["parameters"]
    with tempfile.TemporaryDirectory(prefix="vulnflow-external-validation-execution-") as temporary:
        snapshot = Path(temporary) / "source"
        source_before = copy_verified_public_source(ROOT, snapshot)
        request_binding_file = Path(temporary) / "request-binding.json"
        _write_json(request_binding_file, evidence_request_binding(request_dir, request))
        command = [
            sys.executable,
            "scripts/external_validation_gate.py",
            "--mode",
            "collect",
            "--output-dir",
            str(evidence_output_dir),
            "--request-binding-file",
            str(request_binding_file),
            "--minimum-scanner-files",
            str(parameters["minimum_scanner_files"]),
            "--soak-iterations",
            str(parameters["soak_iterations"]),
        ]
        if scanner_dir is not None:
            command.extend(["--scanner-dir", str(scanner_dir)])
        if chromium:
            command.extend(["--chromium", chromium])
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            command,
            cwd=snapshot,
            env=env,
            timeout=max(300, int(timeout_seconds)),
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError(f"external validation collector exited {result.returncode}")
        source_after = require_public_source(snapshot)
        if source_before["identity"] != source_after["identity"]:
            raise RuntimeError("public execution snapshot changed during external validation")
        statement = sign_response_bundle(
            request_dir=request_dir,
            requester_public_key_file=requester_public_key_file,
            evidence_dir=evidence_output_dir,
            operator_private_key_file=operator_private_key_file,
            output_dir=output_dir,
            runner_label=runner_label,
            source_attestation_before=source_before,
            source_attestation_after=source_after,
            source_root=snapshot,
        )
        return statement, result.returncode


def _render(report: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    print(text, end="")
    if output:
        _write_json(output, report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate-key")
    generate.add_argument("--key-id", required=True)
    generate.add_argument("--private-output", type=Path, required=True)
    generate.add_argument("--public-output", type=Path, required=True)

    request = sub.add_parser("create-request")
    request.add_argument("--private-key-file", type=Path, required=True)
    request.add_argument("--operator-public-key-file", type=Path, required=True)
    request.add_argument("--output-dir", type=Path, required=True)
    request.add_argument("--target-name", required=True)
    request.add_argument("--lifetime-seconds", type=int, default=86400)
    request.add_argument("--minimum-scanner-files", type=int, default=20)
    request.add_argument("--soak-iterations", type=int, default=12)

    verify_request_parser = sub.add_parser("verify-request")
    verify_request_parser.add_argument("request_dir", type=Path)
    verify_request_parser.add_argument("--requester-public-key-file", type=Path, required=True)
    verify_request_parser.add_argument("--json-output", type=Path)

    sign = sub.add_parser("sign-response")
    sign.add_argument("--request-dir", type=Path, required=True)
    sign.add_argument("--requester-public-key-file", type=Path, required=True)
    sign.add_argument("--evidence-dir", type=Path, required=True)
    sign.add_argument("--operator-private-key-file", type=Path, required=True)
    sign.add_argument("--output-dir", type=Path, required=True)
    sign.add_argument("--runner-label", required=True)

    execute = sub.add_parser("execute-request")
    execute.add_argument("--request-dir", type=Path, required=True)
    execute.add_argument("--requester-public-key-file", type=Path, required=True)
    execute.add_argument("--operator-private-key-file", type=Path, required=True)
    execute.add_argument("--output-dir", type=Path, required=True)
    execute.add_argument("--evidence-output-dir", type=Path, required=True)
    execute.add_argument("--runner-label", required=True)
    execute.add_argument("--scanner-dir", type=Path)
    execute.add_argument("--chromium", default="")
    execute.add_argument("--timeout-seconds", type=int, default=3600)

    verify = sub.add_parser("verify-response")
    verify.add_argument("response_dir", type=Path)
    verify.add_argument("--expected-request-dir", type=Path, required=True)
    verify.add_argument("--requester-public-key-file", type=Path, required=True)
    verify.add_argument("--operator-public-key-file", type=Path, required=True)
    verify.add_argument("--without-source-tree-binding", action="store_true")
    verify.add_argument("--json-output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "generate-key":
            private, public = generate_keypair(key_id=args.key_id)
            _write_json(args.private_output, private, private=True)
            _write_json(args.public_output, public)
            _render({"private_key_file": str(args.private_output), "public_key_file": str(args.public_output), "public_key_fingerprint": public["public_key_fingerprint"]}, None)
            return 0
        if args.command == "create-request":
            statement = create_request_bundle(
                output_dir=args.output_dir,
                private_key_file=args.private_key_file,
                operator_public_key_file=args.operator_public_key_file,
                target_name=args.target_name,
                lifetime_seconds=args.lifetime_seconds,
                minimum_scanner_files=args.minimum_scanner_files,
                soak_iterations=args.soak_iterations,
            )
            _render(statement, None)
            return 0
        if args.command == "verify-request":
            statement = verify_request_bundle(
                args.request_dir,
                requester_public_key_file=args.requester_public_key_file,
            )
            _render({"passed": True, "request": statement}, args.json_output)
            return 0
        if args.command == "sign-response":
            statement = sign_response_bundle(
                request_dir=args.request_dir,
                requester_public_key_file=args.requester_public_key_file,
                evidence_dir=args.evidence_dir,
                operator_private_key_file=args.operator_private_key_file,
                output_dir=args.output_dir,
                runner_label=args.runner_label,
            )
            _render(statement, None)
            return 0
        if args.command == "execute-request":
            statement, collector_exit = execute_request(
                request_dir=args.request_dir,
                requester_public_key_file=args.requester_public_key_file,
                operator_private_key_file=args.operator_private_key_file,
                output_dir=args.output_dir,
                evidence_output_dir=args.evidence_output_dir,
                runner_label=args.runner_label,
                scanner_dir=args.scanner_dir,
                chromium=args.chromium,
                timeout_seconds=args.timeout_seconds,
            )
            _render({"collector_exit_code": collector_exit, "response": statement}, None)
            return 0
        if args.command == "verify-response":
            report = verify_response_bundle(
                args.response_dir,
                expected_request_dir=args.expected_request_dir,
                requester_public_key_file=args.requester_public_key_file,
                operator_public_key_file=args.operator_public_key_file,
                source_root=None if args.without_source_tree_binding else ROOT,
            )
            _render(report, args.json_output)
            return 0 if report["integrity_passed"] else 1
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"external validation exchange failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
