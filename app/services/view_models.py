"""Read-model composition helpers with explicit repository dependencies."""
from __future__ import annotations
from app.ui_i18n import format_items, translate_message

from typing import Any, Callable


def campaign_member_ids(
    db_path: Any,
    *,
    finding_ids: list[str],
    cve_id: str = "",
    list_findings_fn: Callable[..., list[dict[str, Any]]],
) -> list[str]:
    ids = list(dict.fromkeys(str(fid).strip() for fid in finding_ids if str(fid).strip()))
    normalized_cve = str(cve_id or "").strip().upper()
    if normalized_cve:
        ids.extend(
            row["finding_id"] for row in list_findings_fn(db_path)
            if str(row.get("cve_id") or "").upper() == normalized_cve
            and str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"
        )
    return list(dict.fromkeys(ids))


def evidence_with_custody(
    db_path: Any,
    *,
    finding_id: str,
    list_evidence_artifacts_fn: Callable[..., list[dict[str, Any]]],
    list_custody_events_fn: Callable[..., list[dict[str, Any]]],
    verify_custody_chain_fn: Callable[..., dict[str, Any]],
) -> list[dict[str, Any]]:
    items = list_evidence_artifacts_fn(db_path, finding_id=finding_id, limit=500)
    for item in items:
        evidence_id = str(item.get("evidence_id") or "")
        item["custody_events"] = list_custody_events_fn(db_path, evidence_id, limit=100)
        item["custody_integrity"] = verify_custody_chain_fn(db_path, evidence_id)
    return items
