from __future__ import annotations

"""Factual scanner compatibility report construction."""

from collections import Counter
from typing import Any

from app.services.finding_imports import CANONICAL_IMPORT_FIELDS, map_import_rows
from app.services.scanner_compatibility_evaluation import CVE_RE


def _nonempty_count(rows: list[dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if str(row.get(field) or "").strip())


def _percent(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return max(0, min(100, round(numerator * 100 / denominator)))


def _source_item_count(parsed: dict[str, Any]) -> int:
    metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
    for key in ("report_items", "result_count"):
        value = metadata.get(key)
        try:
            if int(value) >= 0:
                return int(value)
        except (TypeError, ValueError):
            pass
    source_rows = {
        int(value) for value in parsed.get("source_rows", []) if str(value).isdigit()
    }
    for error in parsed.get("source_errors", []):
        try:
            source_rows.add(int(error.get("row_number")))
        except (TypeError, ValueError, AttributeError):
            pass
    return len(source_rows) or len(parsed.get("rows", [])) + len(parsed.get("source_errors", []))


def _canonical_duplicate_count(rows: list[dict[str, Any]]) -> int:
    seen: set[tuple[str, str, str, str]] = set()
    duplicates = 0
    for row in rows:
        key = (
            str(row.get("asset_name") or row.get("ip_address") or "").strip().casefold(),
            str(row.get("cve_id") or "").strip().upper(),
            str(row.get("product") or "").strip().casefold(),
            str(row.get("component") or "").strip().casefold(),
        )
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)
    return duplicates


def build_scanner_compatibility_report(
    evaluation: dict[str, Any],
    *,
    filename: str = "",
) -> dict[str, Any]:
    """Build a non-scoring compatibility report from one import evaluation."""

    parsed = evaluation
    mapping = dict(parsed.get("mapping") or {})
    if "valid_rows" in parsed:
        mapped_rows = list(parsed.get("valid_rows") or [])
        errors = list(parsed.get("errors") or [])
        mapped_row_count = int(parsed.get("mapped_row_count") or len(mapped_rows))
    else:
        mapped_rows, _, mapping_errors = map_import_rows(
            list(parsed.get("rows") or []),
            list(parsed.get("source_rows") or []),
            mapping,
        )
        errors = list(parsed.get("source_errors") or []) + list(mapping_errors)
        mapped_row_count = len(mapped_rows)

    valid_rows = [
        row
        for row in mapped_rows
        if str(row.get("product") or "").strip()
        and CVE_RE.fullmatch(str(row.get("cve_id") or "").strip())
    ]
    source_items = _source_item_count(parsed)
    source_errors = list(parsed.get("source_errors") or [])
    unsupported_source_items = len(source_errors)
    unique_assets = {
        str(row.get("asset_name") or row.get("ip_address") or "").strip()
        for row in valid_rows
        if str(row.get("asset_name") or row.get("ip_address") or "").strip()
    }
    mapped_fields = [name for name, source in mapping.items() if str(source or "").strip()]
    field_coverage = {
        field: {
            "count": _nonempty_count(valid_rows, field),
            "percent": _percent(_nonempty_count(valid_rows, field), len(valid_rows)),
        }
        for field in (
            "asset_name",
            "ip_address",
            "fqdn",
            "cvss",
            "component",
            "notes",
            "patch_available",
        )
    }
    missing_recommended = [
        field
        for field in ("asset_name", "cvss", "notes")
        if field_coverage[field]["count"] == 0
    ]
    duplicate_rows = _canonical_duplicate_count(valid_rows)
    parser_warnings = [
        str(item) for item in parsed.get("parser_warnings", []) if str(item).strip()
    ]
    warnings = list(dict.fromkeys(parser_warnings))
    if duplicate_rows:
        warnings.append(
            f"동일 자산·CVE·제품·구성요소 조합이 {duplicate_rows:,}건 중복됩니다."
        )

    if not valid_rows:
        status = "BLOCKED"
        conclusion = "현재 파일에서 반영 가능한 CVE 취약점을 찾지 못했습니다."
    elif errors or unsupported_source_items:
        status = "REVIEW"
        conclusion = "일부 항목은 반영할 수 있지만 제외·오류 항목을 검토해야 합니다."
    elif warnings:
        status = "REVIEW"
        conclusion = "반영은 가능하지만 파서 경고 또는 중복 항목을 검토해야 합니다."
    elif missing_recommended:
        status = "REVIEW"
        conclusion = "필수 항목은 반영 가능하지만 자산·위험도·설명 정보가 부족합니다."
    else:
        status = "READY"
        conclusion = "현재 파서와 매핑 기준으로 바로 반영 가능한 파일입니다."

    error_reasons = Counter(str(item.get("message") or "알 수 없는 오류") for item in errors)
    return {
        "format": "vulnflow-scanner-compatibility/1",
        "filename": filename,
        "detected_format": str(parsed.get("detected_format") or ""),
        "adapter": str(parsed.get("adapter") or "generic"),
        "status": status,
        "conclusion": conclusion,
        "source_items": source_items,
        "expanded_rows": mapped_row_count,
        "importable_rows": len(valid_rows),
        "unsupported_source_items": unsupported_source_items,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "warnings": warnings,
        "duplicate_rows": duplicate_rows,
        "unique_assets": len(unique_assets),
        "mapped_fields": mapped_fields,
        "unmapped_fields": [
            str(item["name"])
            for item in CANONICAL_IMPORT_FIELDS
            if str(item["name"]) not in mapped_fields
        ],
        "missing_recommended_fields": missing_recommended,
        "field_coverage": field_coverage,
        "top_error_reasons": [
            {"message": message, "count": count}
            for message, count in error_reasons.most_common(10)
        ],
        "metadata": dict(parsed.get("metadata") or {}),
        "parser_contract": {
            "xml_doctype_entity_blocked": True,
            "xml_max_depth": 128,
            "xml_max_nodes": 250000,
            "max_expanded_rows": 5000,
        },
        "limitations": [
            "CVE가 없는 스캐너 플러그인 결과는 현재 finding 모델에 반영되지 않습니다.",
            "READY는 파일 구조 호환을 의미하며 스캐너 전체 버전 호환 보증은 아닙니다.",
            "snapshot 반영 전에는 오류가 0건인지 별도로 확인해야 합니다.",
        ],
    }
