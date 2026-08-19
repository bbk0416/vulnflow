"""Public scanner-aware finding import facade."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.settings import MAX_CSV_ROWS
from app.services.finding_import_common import (
    CANONICAL_FIELD_NAMES,
    CANONICAL_IMPORT_FIELDS,
    SUPPORTED_IMPORT_FORMATS,
    _HEADER_ALIASES,
    _clean_cell,
    _extract_cves,
    _header_key,
)
from app.services.finding_import_preview import (
    create_preview_session,
    delete_preview_session,
    load_preview_session,
    prune_preview_sessions,
)
from app.services.finding_import_scanners import (
    _local_name,
    _nessus_rows,
    _openvas_csv_rows,
    _openvas_xml_rows,
    _safe_xml_root,
)
from app.services.finding_import_tabular import _csv_rows, _xlsx_rows

def detect_import_format(filename: str, content: bytes, format_hint: str = "auto") -> str:
    hint = str(format_hint or "auto").strip().casefold()
    if hint not in SUPPORTED_IMPORT_FORMATS:
        raise ValueError("지원하지 않는 가져오기 형식입니다.")
    suffix = Path(filename or "").suffix.casefold()
    if hint != "auto":
        if hint == "openvas" and suffix in {".csv", ".txt"}:
            return "openvas_csv"
        if hint == "openvas":
            return "openvas_xml"
        return hint
    stripped = content.lstrip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].lstrip()
    if suffix == ".nessus" or stripped.startswith(b"<NessusClientData_v2"):
        return "nessus"
    if suffix == ".xlsx" or content.startswith(b"PK\x03\x04"):
        return "xlsx"
    if (
        suffix in {".xml", ".omp"}
        or stripped.startswith(b"<?xml")
        or stripped.startswith(b"<report")
        or stripped.startswith(b"<get_reports_response")
    ):
        root = _safe_xml_root(content)
        if _local_name(root.tag) == "nessusclientdata_v2":
            return "nessus"
        return "openvas_xml"
    if suffix in {".csv", ".txt", ""}:
        parsed = _csv_rows(content)
        keys = {_header_key(header) for header in parsed["headers"]}
        has_cve_header = bool(keys & {"cve", "cves", "cve ids", "cve references"})
        current_greenbone = (
            {"vulnerability name", "cve references"} <= keys
            and bool(keys & {"host name", "ip address"})
            and bool(keys & {"qod", "solution type", "port protocol"})
        )
        if (
            ({"nvt name", "cves"} <= keys)
            or ({"nvtname", "cve"} <= keys)
            or ("vt name" in keys and has_cve_header)
            or current_greenbone
        ):
            return "openvas_csv"
        return "csv"
    raise ValueError("지원 형식은 CSV, XLSX, Nessus(.nessus), OpenVAS CSV/XML입니다.")

def auto_map_headers(headers: list[str], *, canonical: bool = False) -> dict[str, str]:
    header_by_key: dict[str, str] = {}
    for header in headers:
        header_by_key.setdefault(_header_key(header), header)
    mapping: dict[str, str] = {field: "" for field in CANONICAL_FIELD_NAMES}
    if canonical:
        for field in CANONICAL_FIELD_NAMES:
            if field in headers:
                mapping[field] = field
        return mapping
    for field, aliases in _HEADER_ALIASES.items():
        for alias in aliases:
            matched = header_by_key.get(_header_key(alias))
            if matched:
                mapping[field] = matched
                break
    if not mapping["product"] and mapping.get("component"):
        mapping["product"] = mapping["component"]
    return mapping

def parse_import_file(content: bytes, *, filename: str, format_hint: str = "auto") -> dict[str, Any]:
    detected = detect_import_format(filename, content, format_hint)
    if detected == "xlsx":
        parsed = _xlsx_rows(content)
        adapter = "generic"
    elif detected == "nessus":
        parsed = _nessus_rows(content)
        adapter = "nessus"
    elif detected == "openvas_xml":
        parsed = _openvas_xml_rows(content)
        adapter = "openvas"
    else:
        parsed = _csv_rows(content)
        if detected == "openvas_csv":
            parsed = _openvas_csv_rows(parsed)
            adapter = "openvas"
        else:
            adapter = "generic"
    canonical = detected in {"nessus", "openvas_xml", "openvas_csv"}
    mapping = auto_map_headers(parsed["headers"], canonical=canonical)
    source_suggestion = "nessus" if detected == "nessus" else "openvas" if detected.startswith("openvas") else "manual"
    return {
        "detected_format": detected,
        "adapter": adapter,
        "headers": parsed["headers"],
        "rows": parsed["rows"],
        "source_rows": parsed["source_rows"],
        "source_errors": parsed.get("source_errors", []),
        "parser_warnings": parsed.get("parser_warnings", []),
        "metadata": parsed.get("metadata", {}),
        "mapping": mapping,
        "scanner_source_suggestion": source_suggestion,
    }

def _mapped_value(raw: dict[str, Any], mapping: dict[str, str], field: str) -> str:
    source = str(mapping.get(field) or "").strip()
    return _clean_cell(raw.get(source)) if source else ""

def map_import_rows(
    raw_rows: list[dict[str, Any]],
    source_rows: list[int],
    mapping: dict[str, str],
) -> tuple[list[dict[str, Any]], list[int], list[dict[str, Any]]]:
    mapped_rows: list[dict[str, Any]] = []
    mapped_source_rows: list[int] = []
    mapping_errors: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_rows):
        row_number = source_rows[index] if index < len(source_rows) else index + 2
        mapped = {field: _mapped_value(raw, mapping, field) for field in CANONICAL_FIELD_NAMES}
        if not mapped["product"] and mapped.get("component"):
            mapped["product"] = mapped["component"]
        if not mapped["asset_name"] and mapped.get("ip_address"):
            mapped["asset_name"] = mapped["ip_address"]
        cves = _extract_cves(mapped.get("cve_id"))
        if not cves:
            mapped_rows.append(mapped)
            mapped_source_rows.append(row_number)
            continue
        for cve in cves:
            expanded = dict(mapped)
            expanded["cve_id"] = cve
            mapped_rows.append(expanded)
            mapped_source_rows.append(row_number)
            if len(mapped_rows) > MAX_CSV_ROWS:
                raise ValueError(f"CVE 확장 결과는 최대 {MAX_CSV_ROWS:,}건까지 지원합니다.")
    return mapped_rows, mapped_source_rows, mapping_errors

def import_format_label(value: str) -> str:
    return {
        "csv": "일반 CSV",
        "xlsx": "Excel XLSX",
        "nessus": "Nessus .nessus",
        "openvas_csv": "OpenVAS/Greenbone CSV",
        "openvas_xml": "OpenVAS/Greenbone XML",
    }.get(value, value)

__all__ = [
    "CANONICAL_IMPORT_FIELDS",
    "SUPPORTED_IMPORT_FORMATS",
    "auto_map_headers",
    "create_preview_session",
    "delete_preview_session",
    "detect_import_format",
    "import_format_label",
    "load_preview_session",
    "map_import_rows",
    "parse_import_file",
    "prune_preview_sessions",
]
