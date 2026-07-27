from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.db import connect
from app.repositories.audit import add_audit_event
from app.services.config_drift import (
    canonical_json,
    compare_snapshots,
    get_active_baseline,
    normalized_snapshot,
    snapshot_hash,
)

MAX_TARGET_BYTES = 256 * 1024
MAX_WINDOW_DAYS = 30
STATUSES = {"PENDING", "APPROVED", "REJECTED", "APPLIED", "CANCELLED"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_time(value: str, *, field: str) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field} 값이 필요합니다.")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{field}은 ISO-8601 날짜·시간이어야 합니다.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _normalize_window(window_start: str, window_end: str) -> tuple[str, str]:
    start = _parse_time(window_start, field="window_start")
    end = _parse_time(window_end, field="window_end")
    if end <= start:
        raise ValueError("변경 종료 시각은 시작 시각보다 늦어야 합니다.")
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise ValueError(f"변경 창구는 최대 {MAX_WINDOW_DAYS}일까지 설정할 수 있습니다.")
    if end < datetime.now(timezone.utc):
        raise ValueError("이미 종료된 변경 창구는 등록할 수 없습니다.")
    return start.isoformat(), end.isoformat()


def _secret_material_present(value: Any, path: str = "") -> bool:
    """Reject raw secret-bearing fields in uploaded redacted target snapshots."""
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).strip().lower()
            child_path = f"{path}.{name}" if path else name
            sensitive = name in {
                "password", "passwd", "token", "api_token", "secret", "client_secret",
                "private_key", "credential", "authorization", "cookie",
            }
            if sensitive and child not in (None, "", False, 0, [], {}):
                return True
            if _secret_material_present(child, child_path):
                return True
        return False
    if isinstance(value, list):
        return any(_secret_material_present(item, path) for item in value)
    return False


def validate_target_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("목표 구성 스냅샷은 JSON 객체여야 합니다.")
    if _secret_material_present(value):
        raise ValueError("목표 구성에는 비밀번호·토큰·비밀키 원문을 포함할 수 없습니다.")
    snapshot = normalized_snapshot(value)
    encoded = canonical_json(snapshot).encode("utf-8")
    if len(encoded) > MAX_TARGET_BYTES:
        raise ValueError("목표 구성 스냅샷이 허용 크기를 초과했습니다.")
    if not isinstance(snapshot.get("settings"), dict):
        raise ValueError("목표 구성 settings가 올바르지 않습니다.")
    return snapshot


def _row_to_request(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["target_snapshot"] = json.loads(item.pop("target_snapshot_json"))
    item["impact"] = json.loads(item.pop("impact_json"))
    now = datetime.now(timezone.utc)
    start = _parse_time(item["window_start"], field="window_start")
    end = _parse_time(item["window_end"], field="window_end")
    if now < start:
        window_state = "SCHEDULED"
    elif now > end:
        window_state = "EXPIRED"
    else:
        window_state = "OPEN"
    item["window_state"] = window_state
    return item


def get_change_request(db_path: str | Path, request_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM config_change_requests WHERE request_id=?", (str(request_id),)
        ).fetchone()
    return _row_to_request(row) if row else None


def list_change_requests(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM config_change_requests "
            "ORDER BY CASE status WHEN 'PENDING' THEN 0 WHEN 'APPROVED' THEN 1 ELSE 2 END, "
            "requested_at DESC, request_id DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    return [_row_to_request(row) for row in rows]


def create_change_request(
    db_path: str | Path,
    target_audit: dict[str, Any],
    *,
    actor: str,
    title: str,
    reason: str,
    rollback_plan: str,
    window_start: str,
    window_end: str,
) -> dict[str, Any]:
    baseline = get_active_baseline(db_path)
    if not baseline:
        raise ValueError("활성 구성 기준선이 없습니다.")
    title = str(title or "").strip()[:200]
    reason = str(reason or "").strip()[:1500]
    rollback_plan = str(rollback_plan or "").strip()[:4000]
    if not title:
        raise ValueError("변경 제목이 필요합니다.")
    if not reason:
        raise ValueError("변경 사유가 필요합니다.")
    if not rollback_plan:
        raise ValueError("롤백 계획이 필요합니다.")
    start, end = _normalize_window(window_start, window_end)
    target = validate_target_snapshot(target_audit)
    target_digest = snapshot_hash(target)
    if target_digest == str(baseline["config_hash"]):
        raise ValueError("목표 구성이 현재 활성 기준선과 동일합니다.")
    impact = compare_snapshots(baseline["snapshot"], target)
    request_id = f"cfgchg-{uuid.uuid4().hex}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        duplicate = conn.execute(
            "SELECT request_id FROM config_change_requests "
            "WHERE baseline_id=? AND target_hash=? AND status IN ('PENDING','APPROVED') LIMIT 1",
            (baseline["baseline_id"], target_digest),
        ).fetchone()
        if duplicate:
            conn.rollback()
            raise ValueError("같은 기준선과 목표 구성에 대한 대기·승인 요청이 이미 있습니다.")
        conn.execute(
            "INSERT INTO config_change_requests("
            "request_id,baseline_id,baseline_hash,target_hash,target_snapshot_json,impact_json,status,title,reason,rollback_plan,"
            "window_start,window_end,requested_by,requested_at,row_version"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                request_id, baseline["baseline_id"], baseline["config_hash"], target_digest,
                canonical_json(target), canonical_json(impact), "PENDING", title, reason,
                rollback_plan, start, end, actor, now,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="CONFIG_CHANGE_REQUESTED",
            summary=f"구성 변경 승인을 요청했습니다: {title}",
            details={
                "request_id": request_id,
                "baseline_id": baseline["baseline_id"],
                "target_hash": target_digest,
                "change_count": impact["change_count"],
                "severity": impact["severity"],
                "window_start": start,
                "window_end": end,
            },
            actor=actor,
            created_at=now,
            conn=conn,
        )
        conn.commit()
    return get_change_request(db_path, request_id) or {}


def decide_change_request(
    db_path: str | Path,
    request_id: str,
    *,
    actor: str,
    decision: str,
    note: str = "",
) -> dict[str, Any]:
    decision = str(decision or "").strip().upper()
    if decision not in {"APPROVE", "REJECT"}:
        raise ValueError("decision은 APPROVE 또는 REJECT여야 합니다.")
    note = str(note or "").strip()[:1500]
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM config_change_requests WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if not row:
            conn.rollback()
            raise KeyError(request_id)
        if str(row["status"]) != "PENDING":
            conn.rollback()
            raise ValueError("대기 중인 변경 요청만 승인·반려할 수 있습니다.")
        if str(row["requested_by"]) == str(actor):
            conn.rollback()
            raise ValueError("변경 요청자는 자신의 요청을 승인·반려할 수 없습니다.")
        active = conn.execute(
            "SELECT baseline_id,config_hash FROM config_baselines WHERE status='ACTIVE' LIMIT 1"
        ).fetchone()
        if not active or str(active["baseline_id"]) != str(row["baseline_id"]) or str(active["config_hash"]) != str(row["baseline_hash"]):
            conn.rollback()
            raise ValueError("요청 이후 활성 기준선이 변경되었습니다. 새 영향분석이 필요합니다.")
        if _parse_time(str(row["window_end"]), field="window_end") < datetime.now(timezone.utc):
            conn.rollback()
            raise ValueError("변경 창구가 이미 종료되었습니다.")
        new_status = "APPROVED" if decision == "APPROVE" else "REJECTED"
        updated = conn.execute(
            "UPDATE config_change_requests SET status=?,decided_by=?,decision_note=?,decided_at=?,row_version=row_version+1 "
            "WHERE request_id=? AND status='PENDING' AND row_version=?",
            (new_status, actor, note, now, request_id, int(row["row_version"])),
        )
        if updated.rowcount != 1:
            conn.rollback()
            raise ValueError("변경 요청이 동시에 수정되었습니다.")
        add_audit_event(
            db_path,
            finding_id=None,
            event_type=f"CONFIG_CHANGE_{new_status}",
            summary=f"구성 변경 요청을 {('승인' if new_status == 'APPROVED' else '반려')}했습니다.",
            details={"request_id": request_id, "note": note},
            actor=actor,
            created_at=now,
            conn=conn,
        )
        conn.commit()
    return get_change_request(db_path, request_id) or {}


def evaluate_change_control(db_path: str | Path, audit: dict[str, Any], drift: dict[str, Any]) -> dict[str, Any]:
    result = dict(drift)
    result["control_status"] = "NO_CHANGE"
    result["change_request"] = None
    if drift.get("status") != "DRIFT" or not drift.get("baseline"):
        return result
    current_hash = str(drift.get("current_hash") or "")
    baseline_id = str(drift["baseline"].get("baseline_id") or "")
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM config_change_requests WHERE baseline_id=? AND target_hash=? "
            "AND status IN ('PENDING','APPROVED') ORDER BY requested_at DESC LIMIT 1",
            (baseline_id, current_hash),
        ).fetchone()
    if not row:
        result["control_status"] = "UNAPPROVED"
        return result
    request = _row_to_request(row)
    effective = str(request["status"])
    if request["window_state"] == "EXPIRED":
        effective = "EXPIRED"
    elif request["status"] == "APPROVED" and request["window_state"] == "OPEN":
        effective = "APPROVED_WINDOW"
    elif request["status"] == "APPROVED":
        effective = "APPROVED_SCHEDULED"
    result["control_status"] = effective
    result["change_request"] = {
        key: request.get(key)
        for key in (
            "request_id", "status", "title", "window_start", "window_end", "window_state",
            "requested_by", "requested_at", "decided_by", "decided_at",
        )
    }
    return result


def promote_change_request(
    db_path: str | Path,
    request_id: str,
    current_audit: dict[str, Any],
    *,
    actor: str,
    note: str = "",
) -> dict[str, Any]:
    current = validate_target_snapshot(current_audit)
    current_hash = snapshot_hash(current)
    note = str(note or "").strip()[:1000]
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM config_change_requests WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if not row:
            conn.rollback()
            raise KeyError(request_id)
        if str(row["status"]) != "APPROVED":
            conn.rollback()
            raise ValueError("승인된 변경 요청만 기준선으로 승격할 수 있습니다.")
        now_dt = datetime.now(timezone.utc)
        start = _parse_time(str(row["window_start"]), field="window_start")
        end = _parse_time(str(row["window_end"]), field="window_end")
        if now_dt < start or now_dt > end:
            conn.rollback()
            raise ValueError("승인된 변경 창구가 열려 있지 않습니다.")
        if current_hash != str(row["target_hash"]):
            conn.rollback()
            raise ValueError("현재 구성이 승인된 목표 스냅샷과 일치하지 않습니다.")
        active = conn.execute(
            "SELECT * FROM config_baselines WHERE status='ACTIVE' LIMIT 1"
        ).fetchone()
        if not active or str(active["baseline_id"]) != str(row["baseline_id"]) or str(active["config_hash"]) != str(row["baseline_hash"]):
            conn.rollback()
            raise ValueError("요청 이후 활성 기준선이 변경되었습니다.")
        new_baseline_id = f"cfg-{uuid.uuid4().hex}"
        conn.execute(
            "UPDATE config_baselines SET status='RETIRED',retired_by=?,retired_at=? WHERE status='ACTIVE'",
            (actor, now),
        )
        conn.execute(
            "INSERT INTO config_baselines(baseline_id,config_hash,snapshot_json,status,note,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                new_baseline_id, current_hash, canonical_json(current), "ACTIVE",
                (note or f"Approved change {request_id}")[:1000], actor, now,
            ),
        )
        updated = conn.execute(
            "UPDATE config_change_requests SET status='APPLIED',applied_by=?,applied_at=?,applied_baseline_id=?,"
            "row_version=row_version+1 WHERE request_id=? AND status='APPROVED' AND row_version=?",
            (actor, now, new_baseline_id, request_id, int(row["row_version"])),
        )
        if updated.rowcount != 1:
            conn.rollback()
            raise ValueError("변경 요청이 동시에 수정되었습니다.")
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="CONFIG_CHANGE_APPLIED",
            summary="승인된 구성 변경을 새 기준선으로 승격했습니다.",
            details={
                "request_id": request_id,
                "previous_baseline_id": row["baseline_id"],
                "new_baseline_id": new_baseline_id,
                "target_hash": current_hash,
                "note": note,
            },
            actor=actor,
            created_at=now,
            conn=conn,
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="CONFIG_BASELINE_CREATED",
            summary="승인된 구성 변경에서 새 기준선을 생성했습니다.",
            details={"baseline_id": new_baseline_id, "config_hash": current_hash, "request_id": request_id},
            actor=actor,
            created_at=now,
            conn=conn,
        )
        conn.commit()
    return get_change_request(db_path, request_id) or {}


def change_control_counts(db_path: str | Path) -> dict[str, int]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT status,COUNT(*) AS count FROM config_change_requests GROUP BY status"
        ).fetchall()
    counts = {status.lower(): 0 for status in STATUSES}
    for row in rows:
        counts[str(row["status"]).lower()] = int(row["count"])
    return counts
