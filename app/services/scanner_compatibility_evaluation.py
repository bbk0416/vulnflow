from __future__ import annotations

"""Offline scanner parsing and canonical CVE validation."""

import re
from typing import Any

from app.services.finding_imports import map_import_rows, parse_import_file

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def evaluate_scanner_file(
    content: bytes,
    *,
    filename: str,
    format_hint: str = "auto",
    mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    parsed = parse_import_file(content, filename=filename, format_hint=format_hint)
    active_mapping = dict(parsed["mapping"] if mapping is None else mapping)
    mapped_rows, mapped_source_rows, mapping_errors = map_import_rows(
        parsed["rows"], parsed["source_rows"], active_mapping
    )
    valid_rows: list[dict[str, Any]] = []
    validation_errors: list[dict[str, Any]] = []
    for index, row in enumerate(mapped_rows):
        row_number = mapped_source_rows[index] if index < len(mapped_source_rows) else index + 2
        product = str(row.get("product") or "").strip()
        cve_id = str(row.get("cve_id") or "").strip().upper()
        if not product:
            validation_errors.append({
                "row_number": row_number,
                "message": "제품·취약점명이 비어 있습니다.",
                "raw": row,
            })
            continue
        if cve_id and not CVE_RE.fullmatch(cve_id):
            validation_errors.append({
                "row_number": row_number,
                "message": "유효한 CVE 식별자가 없습니다.",
                "raw": row,
            })
            continue
        normalized = dict(row)
        normalized["cve_id"] = cve_id
        valid_rows.append(normalized)
    return {
        **parsed,
        "mapping": active_mapping,
        "mapped_row_count": len(mapped_rows),
        "valid_rows": valid_rows,
        "errors": list(parsed.get("source_errors") or [])
        + list(mapping_errors)
        + validation_errors,
    }
