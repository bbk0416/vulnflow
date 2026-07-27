"""HTTP input normalization and response shaping helpers.

The functions in this module are deliberately independent from the compatibility entry module.
Runtime-dependent collaborators are supplied explicitly so the historical
the compatibility entry module compatibility surface can remain thin without becoming the owner
of parsing and presentation logic.
"""
from __future__ import annotations

import csv
import hashlib
import io
from datetime import date
from typing import Any, Callable

from app.core.scoring import ALLOWED_STATUSES, ACTIVE_STATUSES, as_bool, exception_state, is_overdue
from app.core.settings import MAX_CSV_ROWS, MAX_NOTES, MAX_REASON, MAX_TEXT


def bounded_text(value: Any, field: str, max_length: int = MAX_TEXT) -> str:
    text = str(value or "").strip()
    if len(text) > max_length:
        raise ValueError(f"{field}은(는) 최대 {max_length}자입니다.")
    return text


def date_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if text:
        try:
            date.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"{field} 날짜 형식은 YYYY-MM-DD여야 합니다.") from exc
    return text


def number(value: Any, field: str, low: float, high: float) -> float:
    try:
        parsed = float(value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}은(는) 숫자여야 합니다.") from exc
    if not low <= parsed <= high:
        raise ValueError(f"{field}은(는) {low}~{high} 범위여야 합니다.")
    return parsed


def normalize_finding_row(
    row: dict[str, Any],
    index: int,
    *,
    scanner_source: str,
    cve_pattern: Any,
    score_callback: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    row = {str(k).strip(): v for k, v in row.items() if k is not None}
    missing = [name for name in ["product", "cve_id"] if not str(row.get(name, "")).strip()]
    if missing:
        raise ValueError(f"{index + 2}행 필수값 누락: {', '.join(missing)}")

    row["product"] = bounded_text(row.get("product"), "product")
    row["cve_id"] = bounded_text(row.get("cve_id"), "cve_id", 40).upper()
    if not cve_pattern.fullmatch(row["cve_id"]):
        raise ValueError(f"{index + 2}행 CVE 형식 오류: {row['cve_id']}")
    supplied_finding_id = str(row.get("finding_id", "")).strip()

    for field in [
        "product_version", "asset_id", "asset_ref_id", "asset_name", "environment", "component",
        "component_version", "owner", "intel_source", "risk_acceptance_approver",
        "cmdb_id", "cloud_instance_id", "fqdn", "ip_address", "mac_address",
    ]:
        row[field] = bounded_text(row.get(field), field)
    row["notes"] = bounded_text(row.get("notes"), "notes", MAX_NOTES)
    row["risk_acceptance_reason"] = bounded_text(
        row.get("risk_acceptance_reason"), "risk_acceptance_reason", MAX_REASON
    )
    if supplied_finding_id:
        row["finding_id"] = bounded_text(supplied_finding_id, "finding_id", 80)
    else:
        identity_fields = [
            scanner_source, row.get("product", ""), row.get("product_version", ""), row.get("asset_id", ""),
            row.get("asset_name", ""), row.get("environment", ""), row.get("cve_id", ""),
            row.get("component", ""), row.get("component_version", ""),
        ]
        identity = "|".join(str(value).strip().casefold() for value in identity_fields)
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()
        row["finding_id"] = f"AUTO-{digest}"
    for field in ["due_date", "exception_expiry", "first_seen_at", "first_scored_at"]:
        row[field] = date_text(row.get(field), field)

    for field in ["kev", "internet_exposed", "patch_available", "compensating_control"]:
        row[field] = int(as_bool(row.get(field)))
    row["cvss"] = number(row.get("cvss"), "cvss", 0, 10)
    row["epss"] = number(row.get("epss"), "epss", 0, 1)
    row["epss_percentile"] = number(row.get("epss_percentile"), "epss_percentile", 0, 1)
    row["asset_criticality"] = int(number(row.get("asset_criticality") or 1, "asset_criticality", 1, 5))
    row["data_sensitivity"] = int(number(row.get("data_sensitivity") or 1, "data_sensitivity", 1, 5))

    status = str(row.get("status") or "OPEN").strip().upper()
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"{index + 2}행 status 허용값 오류: {status}")
    row["status"] = status
    if status == "RISK_ACCEPTED" and (
        not row["exception_expiry"]
        or not row["risk_acceptance_reason"]
        or not row["risk_acceptance_approver"]
    ):
        raise ValueError(f"{index + 2}행 RISK_ACCEPTED에는 예외 만료일·수용 사유·승인자가 필요합니다.")
    row["intel_source"] = row.get("intel_source") or "manual"
    row["scanner_source"] = bounded_text(scanner_source, "scanner_source", 120) or "manual"
    row["record_state"] = "ACTIVE"
    row["row_version"] = int(row.get("row_version") or 1)
    return score_callback(row)


def parse_findings_csv(
    content: bytes,
    *,
    scanner_source: str,
    allow_empty: bool,
    db_path: Any,
    list_findings_fn: Callable[..., list[dict[str, Any]]],
    list_assets_fn: Callable[..., list[dict[str, Any]]],
    normalize_callback: Callable[[dict[str, Any], int, str], dict[str, Any]],
    rescore_callback: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames:
            raise ValueError("CSV 헤더가 없습니다.")
        existing_map = {row["finding_id"]: row for row in list_findings_fn(db_path)}
        asset_rows = list_assets_fn(db_path, status="", limit=5000)
        assets_by_external = {
            str(a.get("external_asset_id") or "").casefold(): a
            for a in asset_rows if str(a.get("external_asset_id") or "").strip()
        }
        assets_by_name = {
            str(a.get("asset_name") or "").casefold(): a
            for a in asset_rows if str(a.get("asset_name") or "").strip()
        }
        preserve_on_update = {
            "status", "owner", "due_date", "exception_expiry",
            "risk_acceptance_reason", "risk_acceptance_approver", "notes",
            "epss", "epss_percentile", "kev", "intel_source", "intel_updated_at", "resolved_at",
            "first_seen_at", "first_scored_at",
        }
        rows: list[dict[str, Any]] = []
        ids: set[str] = set()
        for idx, raw in enumerate(reader):
            if idx >= MAX_CSV_ROWS:
                raise ValueError(f"CSV는 최대 {MAX_CSV_ROWS:,}행까지 지원합니다.")
            raw_row = dict(raw)
            inventory_asset = assets_by_external.get(str(raw_row.get("asset_id") or "").strip().casefold())
            if inventory_asset is None:
                inventory_asset = assets_by_name.get(str(raw_row.get("asset_name") or "").strip().casefold())
            if inventory_asset and str(inventory_asset.get("source") or "") == "inventory":
                raw_row["asset_ref_id"] = inventory_asset.get("asset_ref_id")
                raw_row["asset_name"] = inventory_asset.get("asset_name") or raw_row.get("asset_name")
                raw_row["environment"] = inventory_asset.get("environment") or raw_row.get("environment")
                raw_row["asset_criticality"] = inventory_asset.get("criticality")
                raw_row["data_sensitivity"] = inventory_asset.get("data_sensitivity")
                raw_row["internet_exposed"] = inventory_asset.get("internet_exposed")
            row = normalize_callback(raw_row, idx, scanner_source)
            existing = existing_map.get(row["finding_id"])
            if existing:
                for field in preserve_on_update:
                    row[field] = existing.get(field)
                row = rescore_callback(row)
            if row["finding_id"] in ids:
                raise ValueError(f"업로드 파일 내 finding_id 중복: {row['finding_id']}")
            ids.add(row["finding_id"])
            rows.append(row)
        if not rows and not allow_empty:
            raise ValueError("CSV에 데이터 행이 없습니다.")
        return rows
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError(str(exc)) from exc


def parse_assets_csv(content: bytes) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames:
            raise ValueError("CSV 헤더가 없습니다.")
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for idx, raw in enumerate(reader):
            if idx >= MAX_CSV_ROWS:
                raise ValueError(f"CSV는 최대 {MAX_CSV_ROWS:,}행까지 지원합니다.")
            row = {str(k).strip(): v for k, v in raw.items() if k is not None}
            external_id = bounded_text(row.get("asset_id") or row.get("external_asset_id"), "asset_id", 200)
            asset_name = bounded_text(row.get("asset_name"), "asset_name", 500)
            if not external_id and not asset_name:
                raise ValueError(f"{idx + 2}행은 asset_id 또는 asset_name이 필요합니다.")
            normalized = {
                "asset_id": external_id,
                "asset_name": asset_name or external_id,
                "service_name": bounded_text(row.get("service_name"), "service_name", 500),
                "business_unit": bounded_text(row.get("business_unit"), "business_unit", 500),
                "owner": bounded_text(row.get("owner"), "owner", 500),
                "environment": bounded_text(row.get("environment"), "environment", 120),
                "criticality": int(number(row.get("criticality") or row.get("asset_criticality") or 1, "criticality", 1, 5)),
                "data_sensitivity": int(number(row.get("data_sensitivity") or 1, "data_sensitivity", 1, 5)),
                "internet_exposed": int(as_bool(row.get("internet_exposed"))),
                "tags": bounded_text(row.get("tags"), "tags", 1000),
                "cmdb_id": bounded_text(row.get("cmdb_id"), "cmdb_id", 500),
                "cloud_instance_id": bounded_text(row.get("cloud_instance_id"), "cloud_instance_id", 500),
                "fqdn": bounded_text(row.get("fqdn"), "fqdn", 500),
                "ip_address": bounded_text(row.get("ip_address"), "ip_address", 100),
                "mac_address": bounded_text(row.get("mac_address"), "mac_address", 100),
                "status": str(row.get("status") or "ACTIVE").strip().upper(),
            }
            identity = external_id.casefold() if external_id else "|".join([
                asset_name.casefold(), normalized["service_name"].casefold(), normalized["environment"].casefold()
            ])
            if identity in seen:
                raise ValueError(f"자산 CSV 중복: {external_id or asset_name}")
            seen.add(identity)
            rows.append(normalized)
        if not rows:
            raise ValueError("CSV에 데이터 행이 없습니다.")
        return rows
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError(str(exc)) from exc


def active(row: dict[str, Any]) -> bool:
    return str(row.get("status", "OPEN")).upper() in ACTIVE_STATUSES


def csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def filter_findings(
    findings: list[dict[str, Any]],
    *,
    decision: str = "",
    status: str = "",
    query: str = "",
    overdue: bool = False,
    exception: str = "",
    record_state: str = "",
    scanner_source: str = "",
) -> list[dict[str, Any]]:
    filtered = findings
    if record_state:
        expected_state = str(record_state).upper()
        if expected_state == "CURRENT":
            filtered = [row for row in filtered if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"]
        elif expected_state != "ALL":
            filtered = [row for row in filtered if str(row.get("record_state") or "ACTIVE").upper() == expected_state]
    if scanner_source:
        filtered = [row for row in filtered if str(row.get("scanner_source") or "manual") == scanner_source]
    if decision:
        filtered = [row for row in filtered if row.get("decision") == decision]
    if status:
        filtered = [row for row in filtered if str(row.get("status", "")).upper() == status]
    if overdue:
        filtered = [row for row in filtered if is_overdue(row)]
    if exception:
        filtered = [row for row in filtered if exception_state(row) == exception]
    if query:
        q = query.casefold()
        keys = ["finding_id", "product", "asset_name", "cve_id", "component", "owner"]
        filtered = [
            row for row in filtered
            if q in " ".join(str(row.get(key, "")) for key in keys).casefold()
        ]
    return filtered


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    item = dict(job)
    payload = dict(item.get("payload") or {})
    rows = payload.pop("rows", None)
    if isinstance(rows, list):
        payload["row_count"] = len(rows)
    item["payload"] = payload
    return item


def job_role(job_type: str) -> str:
    privileged = {"MAINTENANCE", "DATABASE_MAINTENANCE", "WEBHOOK_DELIVERY", "RECOVERY_BACKUP", "EVIDENCE_SCAN"}
    return "admin" if str(job_type).upper() in privileged else "operator"


def export_filters_from_values(
    *,
    decision: str = "",
    status: str = "",
    query: str = "",
    overdue: bool = False,
    exception: str = "",
    record_state: str = "ALL",
    scanner_source: str = "",
) -> dict[str, Any]:
    normalized_state = str(record_state or "ALL").strip().upper()
    if normalized_state not in {"ALL", "CURRENT", "ACTIVE", "STALE", "ARCHIVED"}:
        raise ValueError("record_state는 ALL, CURRENT, ACTIVE, STALE, ARCHIVED 중 하나여야 합니다.")
    return {
        "decision": bounded_text(decision, "decision", 80),
        "status": bounded_text(status, "status", 40).upper(),
        "query": bounded_text(query, "query", 500),
        "overdue": bool(overdue),
        "exception": bounded_text(exception, "exception", 40).lower(),
        "record_state": normalized_state,
        "scanner_source": bounded_text(scanner_source, "scanner_source", 120),
    }
