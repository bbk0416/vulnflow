from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any
from datetime import datetime

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event

ALLOWED_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg"}
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json"}
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._()\-가-힣 ]+")
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
SCAN_STATUSES = {"PENDING", "BASELINE_ONLY", "CLEAN", "INFECTED", "ERROR", "NOT_SCANNED", "WAIVED"}
CUSTODY_GENESIS_HASH = "0" * 64
CUSTODY_EVENT_TYPES = {
    "ACQUIRED", "LEGACY_IMPORTED", "SCANNED", "SCAN_WAIVED", "DOWNLOADED",
    "TRANSFERRED", "RETIRED", "RESTORED", "INTEGRITY_VERIFIED",
}
EVIDENCE_SOURCE_TYPES = {"USER_UPLOAD", "SCANNER_EXPORT", "TICKET_ATTACHMENT", "SYSTEM_LOG", "MANUAL_CAPTURE", "OTHER"}
EVIDENCE_ACQUISITION_METHODS = {"UPLOAD", "EXPORT", "API", "CAPTURE", "COLLECTION", "OTHER"}


def _normalize_provenance(source_type: str, source_reference: str, acquisition_method: str, collected_at: str, fallback_time: str) -> tuple[str, str, str, str]:
    source = str(source_type or "USER_UPLOAD").strip().upper()
    method = str(acquisition_method or "UPLOAD").strip().upper()
    reference = str(source_reference or "").strip()[:1000]
    collected = str(collected_at or fallback_time).strip()[:64]
    if source not in EVIDENCE_SOURCE_TYPES:
        raise ValueError(f"허용되지 않은 증거 출처 유형입니다: {source}")
    if method not in EVIDENCE_ACQUISITION_METHODS:
        raise ValueError(f"허용되지 않은 증거 수집 방법입니다: {method}")
    try:
        datetime.fromisoformat(collected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("증거 수집 시각은 ISO 8601 형식이어야 합니다.") from exc
    return source, reference, method, collected


def _custody_details(details: dict[str, Any] | None = None) -> str:
    return json.dumps(details or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _custody_digest(*, evidence_id: str, event_seq: int, event_type: str, actor: str,
                    from_custodian: str, to_custodian: str, purpose: str,
                    details_json: str, created_at: str, prev_hash: str) -> str:
    payload = {
        "evidence_id": evidence_id, "event_seq": int(event_seq), "event_type": event_type,
        "actor": actor, "from_custodian": from_custodian, "to_custodian": to_custodian,
        "purpose": purpose, "details_json": details_json, "created_at": created_at, "prev_hash": prev_hash,
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def record_evidence_custody_event(
    db_path: str | Path, evidence_id: str, *, event_type: str, actor: str,
    from_custodian: str | None = None, to_custodian: str | None = None,
    purpose: str = "", details: dict[str, Any] | None = None, created_at: str | None = None,
    conn=None,
) -> dict[str, Any]:
    event_type = str(event_type or "").strip().upper()
    if event_type not in CUSTODY_EVENT_TYPES:
        raise ValueError(f"허용되지 않은 증거 보관 이벤트입니다: {event_type}")
    actor = str(actor or "system").strip()[:200] or "system"
    owns = conn is None
    connection = conn or connect(db_path)
    try:
        if owns:
            connection.execute("BEGIN IMMEDIATE")
        artifact = connection.execute(
            "SELECT * FROM verification_evidence_artifacts WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
        if artifact is None:
            raise KeyError(evidence_id)
        current = str(artifact["current_custodian"] or artifact["collected_by"] or artifact["uploaded_by"] or actor)
        from_value = current if from_custodian is None else str(from_custodian).strip()[:200]
        to_value = current if to_custodian is None else str(to_custodian).strip()[:200]
        if event_type == "TRANSFERRED" and not to_value:
            raise ValueError("새 보관 책임자가 필요합니다.")
        event_seq = int(artifact["custody_last_seq"] or 0) + 1
        prev_hash = str(artifact["custody_last_hash"] or CUSTODY_GENESIS_HASH)
        created = created_at or utc_now()
        details_json = _custody_details(details)
        event_hash = _custody_digest(
            evidence_id=evidence_id, event_seq=event_seq, event_type=event_type, actor=actor,
            from_custodian=from_value, to_custodian=to_value, purpose=str(purpose or "")[:1500],
            details_json=details_json, created_at=created, prev_hash=prev_hash,
        )
        connection.execute(
            """INSERT INTO evidence_custody_events(
                   evidence_id,event_seq,event_type,actor,from_custodian,to_custodian,purpose,details_json,created_at,prev_hash,event_hash
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (evidence_id, event_seq, event_type, actor, from_value, to_value, str(purpose or "")[:1500],
             details_json, created, prev_hash, event_hash),
        )
        connection.execute(
            "UPDATE verification_evidence_artifacts SET current_custodian=?,custody_last_seq=?,custody_last_hash=? WHERE evidence_id=?",
            (to_value or current, event_seq, event_hash, evidence_id),
        )
        if owns:
            connection.commit()
        return {
            "evidence_id": evidence_id, "event_seq": event_seq, "event_type": event_type,
            "actor": actor, "from_custodian": from_value, "to_custodian": to_value,
            "purpose": str(purpose or "")[:1500], "details": details or {},
            "created_at": created, "prev_hash": prev_hash, "event_hash": event_hash,
        }
    except Exception:
        if owns:
            connection.rollback()
        raise
    finally:
        if owns:
            connection.close()


def list_evidence_custody_events(db_path: str | Path, evidence_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_custody_events WHERE evidence_id=? ORDER BY event_seq DESC LIMIT ?",
            (evidence_id, max(1, min(int(limit), 2000))),
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.get("details_json") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        items.append(item)
    return items


def _verify_evidence_custody_rows(
    artifact: dict[str, Any], rows: list[dict[str, Any]]
) -> dict[str, Any]:
    evidence_id = str(artifact["evidence_id"])
    prev_hash = CUSTODY_GENESIS_HASH
    expected_seq = 1
    issues: list[str] = []
    last_to = ""
    for row in rows:
        event_seq = int(row["event_seq"])
        if event_seq != expected_seq:
            issues.append(f"sequence_gap:{expected_seq}")
        if str(row["prev_hash"]) != prev_hash:
            issues.append(f"prev_hash_mismatch:{event_seq}")
        expected_hash = _custody_digest(
            evidence_id=evidence_id, event_seq=event_seq, event_type=str(row["event_type"]),
            actor=str(row["actor"]), from_custodian=str(row["from_custodian"]),
            to_custodian=str(row["to_custodian"]), purpose=str(row["purpose"]),
            details_json=str(row["details_json"]), created_at=str(row["created_at"]),
            prev_hash=str(row["prev_hash"]),
        )
        if expected_hash != str(row["event_hash"]):
            issues.append(f"event_hash_mismatch:{event_seq}")
        prev_hash = str(row["event_hash"])
        last_to = str(row["to_custodian"] or last_to)
        expected_seq = event_seq + 1
    if int(artifact.get("custody_last_seq") or 0) != len(rows):
        issues.append("artifact_last_seq_mismatch")
    if str(artifact.get("custody_last_hash") or "") != (prev_hash if rows else ""):
        issues.append("artifact_last_hash_mismatch")
    if rows and str(artifact.get("current_custodian") or "") != last_to:
        issues.append("current_custodian_mismatch")
    return {
        "valid": not issues, "evidence_id": evidence_id, "event_count": len(rows),
        "last_seq": len(rows), "last_hash": prev_hash if rows else "",
        "current_custodian": artifact.get("current_custodian"), "issues": issues,
    }


def verify_evidence_custody_chain(db_path: str | Path, evidence_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        artifact_row = conn.execute(
            "SELECT evidence_id,custody_last_seq,custody_last_hash,current_custodian "
            "FROM verification_evidence_artifacts WHERE evidence_id=?",
            (evidence_id,),
        ).fetchone()
        if artifact_row is None:
            raise KeyError(evidence_id)
        event_rows = conn.execute(
            "SELECT * FROM evidence_custody_events WHERE evidence_id=? ORDER BY event_seq",
            (evidence_id,),
        ).fetchall()
    return _verify_evidence_custody_rows(
        dict(artifact_row), [dict(row) for row in event_rows]
    )


def _verify_all_evidence_custody_chains(
    db_path: str | Path, artifacts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    events_by_evidence: dict[str, list[dict[str, Any]]] = {}
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_custody_events ORDER BY evidence_id,event_seq"
        ).fetchall()
    for row in rows:
        item = dict(row)
        events_by_evidence.setdefault(str(item["evidence_id"]), []).append(item)
    return [
        _verify_evidence_custody_rows(
            artifact, events_by_evidence.get(str(artifact["evidence_id"]), [])
        )
        for artifact in artifacts
    ]


def transfer_evidence_custody(db_path: str | Path, evidence_id: str, *, actor: str, to_custodian: str, purpose: str) -> dict[str, Any]:
    to_custodian = str(to_custodian or "").strip()[:200]
    purpose = str(purpose or "").strip()[:1500]
    if not to_custodian:
        raise ValueError("새 보관 책임자가 필요합니다.")
    if not purpose:
        raise ValueError("인계 목적이 필요합니다.")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM verification_evidence_artifacts WHERE evidence_id=?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        if str(row["status"]) != "ACTIVE":
            raise ValueError("활성 증거만 인계할 수 있습니다.")
        current = str(row["current_custodian"] or row["collected_by"] or row["uploaded_by"] or "")
        if current == to_custodian:
            raise ValueError("현재 보관 책임자와 다른 담당자를 지정하세요.")
        event = record_evidence_custody_event(
            db_path, evidence_id, event_type="TRANSFERRED", actor=actor,
            from_custodian=str(row["current_custodian"] or row["collected_by"] or row["uploaded_by"]),
            to_custodian=to_custodian, purpose=purpose, conn=conn,
        )
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="remediation_evidence_transferred",
            summary=f"조치 검증 증거 인계: {row['original_filename']} → {to_custodian}",
            details={"evidence_id": evidence_id, "from": event["from_custodian"], "to": to_custodian, "purpose": purpose},
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_evidence_artifact(db_path, evidence_id) or {}


def record_evidence_access(db_path: str | Path, evidence_id: str, *, actor: str, purpose: str = "download") -> dict[str, Any]:
    return record_evidence_custody_event(
        db_path, evidence_id, event_type="DOWNLOADED", actor=actor, purpose=str(purpose or "download")[:1500],
        details={"access": "download"},
    )


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_original_filename(filename: str) -> str:
    name = Path(str(filename or "evidence.bin")).name.strip().replace("\x00", "")
    name = SAFE_FILENAME_RE.sub("_", name)[:200].strip(" .")
    if not name:
        raise ValueError("증거 파일명이 올바르지 않습니다.")
    return name


def validate_evidence_content(filename: str, content: bytes, *, max_bytes: int) -> dict[str, Any]:
    name = sanitize_original_filename(filename)
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("허용되는 증거 형식은 txt, log, csv, json, pdf, png, jpg입니다.")
    if not content:
        raise ValueError("증거 파일이 비어 있습니다.")
    if len(content) > max(1, int(max_bytes)):
        raise ValueError(f"증거 파일은 최대 {max_bytes // (1024 * 1024)}MB입니다.")
    if suffix in TEXT_EXTENSIONS:
        if b"\x00" in content:
            raise ValueError("텍스트 증거에 NUL 바이트가 포함되어 있습니다.")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("텍스트 증거는 UTF-8이어야 합니다.") from exc
        if suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError("JSON 증거 형식이 올바르지 않습니다.") from exc
        content_type = {".json": "application/json", ".csv": "text/csv"}.get(suffix, "text/plain")
    elif suffix == ".pdf":
        if not content.startswith(b"%PDF-"):
            raise ValueError("PDF 파일 시그니처가 올바르지 않습니다.")
        content_type = "application/pdf"
    elif suffix == ".png":
        if not content.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("PNG 파일 시그니처가 올바르지 않습니다.")
        content_type = "image/png"
    else:
        if not content.startswith(b"\xff\xd8\xff"):
            raise ValueError("JPEG 파일 시그니처가 올바르지 않습니다.")
        content_type = "image/jpeg"
    return {
        "original_filename": name,
        "content_type": content_type,
        "size_bytes": len(content),
        "sha256": _sha256_bytes(content),
    }


def _atomic_write(directory: Path, stored_filename: str, content: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        # Windows and some mounted filesystems may not support POSIX modes.
        pass
    target = directory / stored_filename
    fd, temporary = tempfile.mkstemp(prefix=".evidence-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return target


def store_verification_evidence(
    db_path: str | Path,
    evidence_dir: str | Path,
    *,
    verification_id: str,
    filename: str,
    content: bytes,
    notes: str,
    actor: str,
    max_bytes: int,
    source_type: str = "USER_UPLOAD",
    source_reference: str = "",
    acquisition_method: str = "UPLOAD",
    collected_at: str = "",
) -> dict[str, Any]:
    metadata = validate_evidence_content(filename, content, max_bytes=max_bytes)
    evidence_id = f"EVD-{uuid.uuid4().hex[:16].upper()}"
    stored_filename = f"{evidence_id}.bin"
    evidence_root = Path(evidence_dir)
    with connect(db_path) as conn:
        verification = conn.execute(
            "SELECT verification_id,finding_id,status FROM remediation_verification_requests WHERE verification_id=?",
            (verification_id,),
        ).fetchone()
        if verification is None:
            raise KeyError(verification_id)
        if str(verification["status"]) != "PENDING":
            raise ValueError("대기 중인 검증 요청에만 증거를 추가할 수 있습니다.")
    target = _atomic_write(evidence_root, stored_filename, content)
    try:
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            verification = conn.execute(
                "SELECT verification_id,finding_id,status FROM remediation_verification_requests WHERE verification_id=?",
                (verification_id,),
            ).fetchone()
            if verification is None:
                raise KeyError(verification_id)
            if str(verification["status"]) != "PENDING":
                raise ValueError("대기 중인 검증 요청에만 증거를 추가할 수 있습니다.")
            now = utc_now()
            source_value, reference_value, method_value, collected_value = _normalize_provenance(
                source_type, source_reference, acquisition_method, collected_at, now
            )
            conn.execute(
                """INSERT INTO verification_evidence_artifacts(
                       evidence_id,verification_id,finding_id,stored_filename,original_filename,
                       content_type,size_bytes,sha256,notes,status,uploaded_by,uploaded_at,scan_status,
                       source_type,source_reference,acquisition_method,collected_by,collected_at,current_custodian
                   ) VALUES(?,?,?,?,?,?,?,?,?,'ACTIVE',?,?,'PENDING',?,?,?,?,?,?)""",
                (
                    evidence_id, verification_id, verification["finding_id"], stored_filename,
                    metadata["original_filename"], metadata["content_type"], metadata["size_bytes"],
                    metadata["sha256"], str(notes or "").strip(), actor, now,
                    source_value, reference_value, method_value, actor,
                    collected_value, actor,
                ),
            )
            record_evidence_custody_event(
                db_path, evidence_id, event_type="ACQUIRED", actor=actor, from_custodian="", to_custodian=actor,
                purpose="verification evidence acquisition",
                details={"source_type": source_value, "source_reference": reference_value,
                         "acquisition_method": method_value, "sha256": metadata["sha256"]},
                created_at=collected_value, conn=conn,
            )
            add_audit_event(
                db_path,
                finding_id=verification["finding_id"],
                event_type="remediation_evidence_uploaded",
                summary=f"조치 검증 증거 업로드: {metadata['original_filename']}",
                details={
                    "evidence_id": evidence_id,
                    "verification_id": verification_id,
                    "sha256": metadata["sha256"],
                    "size_bytes": metadata["size_bytes"],
                    "content_type": metadata["content_type"],
                },
                actor=actor,
                conn=conn,
            )
            conn.commit()
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return get_evidence_artifact(db_path, evidence_id) or {}



def _scan_result(status: str, *, engine: str, signature: str = "", details: str = "", error: str = "") -> dict[str, str]:
    normalized = str(status).upper()
    if normalized not in SCAN_STATUSES:
        raise ValueError(f"허용되지 않은 증거 검사 상태입니다: {normalized}")
    return {
        "scan_status": normalized,
        "scan_engine": str(engine)[:120],
        "scan_signature": str(signature)[:500],
        "scan_details": str(details)[:2000],
        "scan_error": str(error)[:2000],
    }


def scan_evidence_path(
    path: str | Path, *, mode: str = "builtin", clamscan_path: str = "clamscan", timeout_seconds: int = 30
) -> dict[str, str]:
    evidence_path = Path(path)
    normalized = str(mode or "builtin").strip().lower()
    if normalized == "disabled":
        return _scan_result("NOT_SCANNED", engine="disabled", details="scanner disabled by configuration")
    if normalized == "builtin":
        content = evidence_path.read_bytes()
        if EICAR_MARKER in content:
            return _scan_result(
                "INFECTED", engine="builtin-baseline", signature="EICAR-Test-Signature",
                details="EICAR test marker detected",
            )
        return _scan_result(
            "BASELINE_ONLY", engine="builtin-baseline", signature="baseline-no-eicar",
            details="EICAR baseline completed; this is not a full malware clean verdict",
        )
    if normalized != "clamscan":
        raise ValueError("VULNFLOW_EVIDENCE_SCANNER_MODE는 builtin, clamscan, disabled 중 하나여야 합니다.")
    executable = shutil.which(clamscan_path) if not Path(clamscan_path).is_file() else clamscan_path
    if not executable:
        return _scan_result("ERROR", engine="clamscan", error="clamscan executable not found")
    try:
        completed = subprocess.run(
            [str(executable), "--no-summary", "--stdout", str(evidence_path)],
            capture_output=True, text=True, timeout=max(1, int(timeout_seconds)), check=False,
        )
    except subprocess.TimeoutExpired:
        return _scan_result("ERROR", engine="clamscan", error="clamscan timeout")
    except OSError as exc:
        return _scan_result("ERROR", engine="clamscan", error=f"clamscan launch failed: {exc}")
    output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
    if completed.returncode == 0:
        return _scan_result("CLEAN", engine="clamscan", details=output)
    if completed.returncode == 1:
        signature = ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped.endswith(" FOUND") or ":" not in stripped:
                continue
            # Split on the final colon so Windows drive letters (for example C:)
            # are not included in the malware signature.
            signature = stripped[:-len(" FOUND")].rsplit(":", 1)[-1].strip()
            break
        return _scan_result("INFECTED", engine="clamscan", signature=signature, details=output)
    return _scan_result("ERROR", engine="clamscan", details=output, error=f"clamscan exit code {completed.returncode}")


def record_evidence_scan_result(
    db_path: str | Path, evidence_id: str, *, result: dict[str, str], actor: str
) -> dict[str, Any]:
    status = str(result.get("scan_status") or "ERROR").upper()
    if status not in SCAN_STATUSES - {"PENDING", "WAIVED"}:
        raise ValueError("검사 결과 상태가 올바르지 않습니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM verification_evidence_artifacts WHERE evidence_id=?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        conn.execute(
            """UPDATE verification_evidence_artifacts
                   SET scan_status=?,scan_engine=?,scan_signature=?,scan_details=?,scanned_at=?,scan_error=?,
                       scan_waived_by='',scan_waived_at='',scan_waiver_reason=''
                 WHERE evidence_id=?""",
            (
                status, str(result.get("scan_engine") or "")[:120], str(result.get("scan_signature") or "")[:500],
                str(result.get("scan_details") or "")[:2000], now, str(result.get("scan_error") or "")[:2000], evidence_id,
            ),
        )
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="remediation_evidence_scanned",
            summary=f"조치 검증 증거 검사: {row['original_filename']} ({status})",
            details={"evidence_id": evidence_id, "verification_id": row["verification_id"], "status": status,
                     "engine": result.get("scan_engine"), "signature": result.get("scan_signature")},
            actor=actor, conn=conn,
        )
        record_evidence_custody_event(
            db_path, evidence_id, event_type="SCANNED", actor=actor, purpose="malware scan",
            details={"status": status, "engine": result.get("scan_engine"), "signature": result.get("scan_signature")},
            conn=conn,
        )
        conn.commit()
    return get_evidence_artifact(db_path, evidence_id) or {}


def scan_evidence_artifact(
    db_path: str | Path, evidence_dir: str | Path, evidence_id: str, *, mode: str = "builtin",
    clamscan_path: str = "clamscan", timeout_seconds: int = 30, actor: str = "system-scanner",
) -> dict[str, Any]:
    artifact = get_evidence_artifact(db_path, evidence_id)
    if artifact is None:
        raise KeyError(evidence_id)
    integrity = verify_evidence_artifact(evidence_dir, artifact)
    if not integrity.get("valid"):
        result = _scan_result("ERROR", engine=mode, error="evidence integrity verification failed before scan")
    else:
        result = scan_evidence_path(
            resolve_evidence_path(evidence_dir, artifact), mode=mode,
            clamscan_path=clamscan_path, timeout_seconds=timeout_seconds,
        )
    return record_evidence_scan_result(db_path, evidence_id, result=result, actor=actor)


def waive_evidence_scan(db_path: str | Path, evidence_id: str, *, actor: str, reason: str) -> dict[str, Any]:
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError("검사 면제 사유가 필요합니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM verification_evidence_artifacts WHERE evidence_id=?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        if str(row["status"]) != "ACTIVE":
            raise ValueError("활성 증거만 검사 면제할 수 있습니다.")
        if str(row["scan_status"]) == "INFECTED":
            raise ValueError("악성으로 탐지된 증거는 면제할 수 없습니다. 보관해제 후 안전한 파일로 교체하세요.")
        if str(row["scan_status"]) == "CLEAN":
            raise ValueError("이미 정상 검사된 증거입니다.")
        conn.execute(
            """UPDATE verification_evidence_artifacts
                   SET scan_status='WAIVED',scan_waived_by=?,scan_waived_at=?,scan_waiver_reason=?
                 WHERE evidence_id=?""",
            (actor, now, reason[:1500], evidence_id),
        )
        add_audit_event(
            db_path, finding_id=row["finding_id"], event_type="remediation_evidence_scan_waived",
            summary=f"조치 검증 증거 검사 면제: {row['original_filename']}",
            details={"evidence_id": evidence_id, "verification_id": row["verification_id"], "reason": reason[:1500]},
            actor=actor, conn=conn,
        )
        record_evidence_custody_event(
            db_path, evidence_id, event_type="SCAN_WAIVED", actor=actor, purpose=reason[:1500],
            details={"verification_id": row["verification_id"]}, conn=conn,
        )
        conn.commit()
    return get_evidence_artifact(db_path, evidence_id) or {}


def evidence_download_allowed(artifact: dict[str, Any], *, require_clean: bool = True) -> bool:
    if str(artifact.get("status") or "") != "ACTIVE":
        return False
    if not require_clean:
        return True
    return str(artifact.get("scan_status") or "PENDING") in {"CLEAN", "WAIVED"}

def list_evidence_artifacts(
    db_path: str | Path, *, verification_id: str = "", finding_id: str = "", status: str = "", limit: int = 500
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if verification_id:
        clauses.append("e.verification_id=?")
        params.append(verification_id)
    if finding_id:
        clauses.append("e.finding_id=?")
        params.append(finding_id)
    if status:
        clauses.append("e.status=?")
        params.append(status.upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 2000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT e.*,v.method,v.status AS verification_status,v.requested_at,v.decided_at,
                       f.cve_id,f.asset_name,f.product,
                       (SELECT COUNT(*) FROM evidence_custody_events c WHERE c.evidence_id=e.evidence_id) AS custody_event_count
                  FROM verification_evidence_artifacts e
                  JOIN remediation_verification_requests v ON v.verification_id=e.verification_id
                  JOIN findings f ON f.finding_id=e.finding_id
                  {where}
                 ORDER BY e.uploaded_at DESC LIMIT ?""",
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_evidence_artifact(db_path: str | Path, evidence_id: str) -> dict[str, Any] | None:
    # Query by the immutable identifier to avoid returning another artifact.
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT e.*,v.method,v.status AS verification_status,f.cve_id,f.asset_name,f.product,
                       (SELECT COUNT(*) FROM evidence_custody_events c WHERE c.evidence_id=e.evidence_id) AS custody_event_count
                 FROM verification_evidence_artifacts e
                 JOIN remediation_verification_requests v ON v.verification_id=e.verification_id
                 JOIN findings f ON f.finding_id=e.finding_id
                WHERE e.evidence_id=?""",
            (evidence_id,),
        ).fetchone()
    return dict(row) if row else None


def retire_evidence_artifact(
    db_path: str | Path, evidence_id: str, *, actor: str, reason: str
) -> dict[str, Any]:
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError("증거 보관해제 사유가 필요합니다.")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT e.*,v.status AS verification_status FROM verification_evidence_artifacts e
                 JOIN remediation_verification_requests v ON v.verification_id=e.verification_id
                WHERE e.evidence_id=?""",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        item = dict(row)
        if item["status"] != "ACTIVE":
            raise ValueError("활성 증거만 보관해제할 수 있습니다.")
        if item["verification_status"] != "PENDING":
            raise ValueError("처리 완료된 검증 요청의 증거는 보관해제할 수 없습니다.")
        now = utc_now()
        conn.execute(
            "UPDATE verification_evidence_artifacts SET status='RETIRED',retired_by=?,retired_at=?,retire_reason=? WHERE evidence_id=?",
            (actor, now, reason, evidence_id),
        )
        add_audit_event(
            db_path,
            finding_id=item["finding_id"],
            event_type="remediation_evidence_retired",
            summary=f"조치 검증 증거 보관해제: {item['original_filename']}",
            details={"evidence_id": evidence_id, "verification_id": item["verification_id"], "reason": reason},
            actor=actor,
            conn=conn,
        )
        record_evidence_custody_event(
            db_path, evidence_id, event_type="RETIRED", actor=actor, purpose=reason,
            details={"verification_id": item["verification_id"]}, conn=conn,
        )
        conn.commit()
    return get_evidence_artifact(db_path, evidence_id) or {}


def resolve_evidence_path(evidence_dir: str | Path, artifact: dict[str, Any]) -> Path:
    stored = Path(str(artifact.get("stored_filename") or "")).name
    if not stored or stored != str(artifact.get("stored_filename") or ""):
        raise ValueError("증거 저장 경로가 올바르지 않습니다.")
    path = Path(evidence_dir) / stored
    if not path.is_file():
        raise FileNotFoundError(stored)
    return path


def verify_evidence_artifact(evidence_dir: str | Path, artifact: dict[str, Any]) -> dict[str, Any]:
    try:
        path = resolve_evidence_path(evidence_dir, artifact)
    except (ValueError, FileNotFoundError) as exc:
        return {"valid": False, "evidence_id": artifact.get("evidence_id"), "issue": str(exc)}
    actual_size = path.stat().st_size
    actual_hash = sha256_file(path)
    issues: list[str] = []
    if actual_size != int(artifact.get("size_bytes") or -1):
        issues.append("size_mismatch")
    if actual_hash != str(artifact.get("sha256") or ""):
        issues.append("sha256_mismatch")
    return {
        "valid": not issues,
        "evidence_id": artifact.get("evidence_id"),
        "stored_filename": artifact.get("stored_filename"),
        "size_bytes": actual_size,
        "sha256": actual_hash,
        "issues": issues,
    }


def _list_evidence_integrity_artifacts(db_path: str | Path) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT evidence_id,stored_filename,size_bytes,sha256,status,scan_status,
                      custody_last_seq,custody_last_hash,current_custodian
                 FROM verification_evidence_artifacts
                ORDER BY evidence_id"""
        ).fetchall()
    return [dict(row) for row in rows]


def verify_evidence_store(db_path: str | Path, evidence_dir: str | Path) -> dict[str, Any]:
    # Integrity verification must cover the complete evidence inventory. The UI list
    # helper intentionally caps results, so using it here could misclassify valid
    # files as unregistered once the repository grew past that cap.
    artifacts = _list_evidence_integrity_artifacts(db_path)
    active_artifacts = [item for item in artifacts if item.get("status") != "PURGED"]
    checked = [verify_evidence_artifact(evidence_dir, item) for item in active_artifacts]
    invalid = [item for item in checked if not item["valid"]]
    known = {str(item.get("stored_filename")) for item in active_artifacts}
    root = Path(evidence_dir)
    unexpected = (
        sorted(path.name for path in root.iterdir() if path.is_file() and path.name not in known)
        if root.exists() else []
    )
    scan_counts: dict[str, int] = {}
    for artifact in artifacts:
        key = str(artifact.get("scan_status") or "PENDING")
        scan_counts[key] = scan_counts.get(key, 0) + 1
    unsafe_count = sum(
        count for status, count in scan_counts.items() if status not in {"CLEAN", "WAIVED"}
    )
    custody = _verify_all_evidence_custody_chains(db_path, artifacts)
    invalid_custody = [item for item in custody if not item.get("valid")]
    return {
        "valid": not invalid and not unexpected and not invalid_custody,
        "artifact_count": len(checked),
        "invalid_count": len(invalid),
        "unexpected_file_count": len(unexpected),
        "unsafe_count": unsafe_count,
        "scan_counts": scan_counts,
        "custody_invalid_count": len(invalid_custody),
        "custody_invalid": invalid_custody,
        "invalid": invalid,
        "unexpected_files": unexpected,
    }
