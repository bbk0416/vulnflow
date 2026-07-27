from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.db import connect
from app.repositories.audit import add_audit_event

DRIFT_FORMAT = "vulnflow-config-baseline/1"
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalized_snapshot(audit: dict[str, Any]) -> dict[str, Any]:
    """Keep only stable, already-redacted configuration material."""
    findings = sorted(
        [
            {
                "code": str(item.get("code") or ""),
                "severity": str(item.get("severity") or ""),
                "message": str(item.get("message") or ""),
            }
            for item in (audit.get("findings") or [])
            if isinstance(item, dict)
        ],
        key=lambda item: (item["severity"], item["code"], item["message"]),
    )
    return {
        "format": DRIFT_FORMAT,
        "posture": str(audit.get("posture") or "unknown"),
        "settings": audit.get("settings") or {},
        "findings": findings,
    }


def snapshot_hash(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(value[key], path))
        return result
    if isinstance(value, list):
        return {prefix: value}
    return {prefix: value}


def _severity(path: str, before: Any, current: Any) -> str:
    high_paths = {
        "settings.authentication.local_fallback_enabled",
        "settings.webhooks.allow_insecure_http",
        "settings.evidence_store.clean_required",
        "settings.recovery.restore_signature_required",
        "settings.audit_integrity.signature_required",
        "settings.integrity_proof_public_signing.public_signature_required",
        "settings.cluster_coordination.enabled",
    }
    medium_prefixes = (
        "settings.authentication.",
        "settings.signing_keys.",
        "settings.audit_integrity.",
        "settings.integrity_proof_public_signing.",
        "settings.recovery.",
        "settings.webhooks.",
        "settings.evidence_store.",
        "settings.workers.",
        "settings.cluster_coordination.",
        "settings.export_storage.",
        "settings.database.",
        "findings",
    )
    if path in high_paths:
        return "HIGH"
    if path.startswith(medium_prefixes):
        return "MEDIUM"
    return "LOW"


def compare_snapshots(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    before_flat = _flatten(baseline)
    current_flat = _flatten(current)
    changes: list[dict[str, Any]] = []
    for path in sorted(set(before_flat) | set(current_flat)):
        before = before_flat.get(path, None)
        after = current_flat.get(path, None)
        if canonical_json(before) == canonical_json(after):
            continue
        changes.append(
            {
                "path": path,
                "before": before,
                "current": after,
                "severity": _severity(path, before, after),
            }
        )
    highest = max((SEVERITY_RANK[item["severity"]] for item in changes), default=0)
    severity = next((name for name, rank in SEVERITY_RANK.items() if rank == highest), "NONE")
    return {
        "drifted": bool(changes),
        "change_count": len(changes),
        "severity": severity,
        "changes": changes,
    }


def get_active_baseline(db_path: str | Path) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM config_baselines WHERE status='ACTIVE' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["snapshot"] = json.loads(item.pop("snapshot_json"))
    return item


def list_baselines(db_path: str | Path, *, limit: int = 20) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT baseline_id,config_hash,status,note,created_by,created_at,retired_by,retired_at "
            "FROM config_baselines ORDER BY CASE status WHEN 'ACTIVE' THEN 0 ELSE 1 END, created_at DESC, baseline_id DESC LIMIT ?",
            (max(1, min(int(limit), 200)),),
        ).fetchall()
    return [dict(row) for row in rows]


def create_baseline(
    db_path: str | Path,
    audit: dict[str, Any],
    *,
    actor: str,
    note: str = "",
) -> dict[str, Any]:
    snapshot = normalized_snapshot(audit)
    digest = snapshot_hash(snapshot)
    baseline_id = f"cfg-{uuid.uuid4().hex}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT baseline_id FROM config_baselines WHERE status='ACTIVE' AND config_hash=?",
            (digest,),
        ).fetchone()
        if existing:
            conn.rollback()
            raise ValueError("현재 구성은 이미 활성 기준선과 동일합니다.")
        conn.execute(
            "UPDATE config_baselines SET status='RETIRED',retired_by=?,retired_at=? WHERE status='ACTIVE'",
            (actor, now),
        )
        conn.execute(
            "INSERT INTO config_baselines(baseline_id,config_hash,snapshot_json,status,note,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (baseline_id, digest, canonical_json(snapshot), "ACTIVE", str(note or "")[:1000], actor, now),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="CONFIG_BASELINE_CREATED",
            summary="구성 기준선을 승인했습니다.",
            details={"baseline_id": baseline_id, "config_hash": digest, "note": str(note or "")[:1000]},
            actor=actor,
            created_at=now,
            conn=conn,
        )
        conn.commit()
    return get_active_baseline(db_path) or {}


def evaluate_drift(db_path: str | Path, audit: dict[str, Any]) -> dict[str, Any]:
    current = normalized_snapshot(audit)
    current_digest = snapshot_hash(current)
    baseline = get_active_baseline(db_path)
    if baseline is None:
        return {
            "status": "NO_BASELINE",
            "baseline": None,
            "current_hash": current_digest,
            "drifted": False,
            "change_count": 0,
            "severity": "NONE",
            "changes": [],
        }
    comparison = compare_snapshots(baseline["snapshot"], current)
    return {
        "status": "DRIFT" if comparison["drifted"] else "IN_SYNC",
        "baseline": {
            key: baseline.get(key)
            for key in ("baseline_id", "config_hash", "note", "created_by", "created_at")
        },
        "current_hash": current_digest,
        **comparison,
    }


def record_drift_check(
    db_path: str | Path,
    audit: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    result = evaluate_drift(db_path, audit)
    baseline = result.get("baseline")
    if not baseline:
        raise ValueError("활성 구성 기준선이 없습니다.")
    check_id = f"cfgchk-{uuid.uuid4().hex}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO config_drift_checks(check_id,baseline_id,current_hash,status,change_count,severity,changes_json,checked_by,checked_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                check_id,
                baseline["baseline_id"],
                result["current_hash"],
                result["status"],
                int(result["change_count"]),
                result["severity"],
                canonical_json(result["changes"]),
                actor,
                now,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="CONFIG_DRIFT_CHECKED",
            summary=f"구성 드리프트 검사를 기록했습니다: {result['status']}",
            details={
                "check_id": check_id,
                "baseline_id": baseline["baseline_id"],
                "current_hash": result["current_hash"],
                "change_count": result["change_count"],
                "severity": result["severity"],
            },
            actor=actor,
            created_at=now,
            conn=conn,
        )
        conn.commit()
    return {"check_id": check_id, "checked_at": now, **result}


def list_drift_checks(db_path: str | Path, *, limit: int = 50) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM config_drift_checks ORDER BY checked_at DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["changes"] = json.loads(item.pop("changes_json"))
        result.append(item)
    return result
