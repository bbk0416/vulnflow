"""OpenVAS and Greenbone CSV/XML adapters for finding imports."""
from __future__ import annotations

from typing import Any

from app.core.settings import MAX_CSV_ROWS
from app.services.finding_import_common import (
    CANONICAL_FIELD_NAMES,
    _clean_cell,
    _extract_cves,
    _fqdn_value,
    _header_key,
    _ip_value,
    _truncate_notes,
)
from app.services.finding_import_xml import (
    _children_by_name,
    _first_text,
    _local_name,
    _reference_cves,
    _safe_xml_document,
)


def _row_value(row: dict[str, Any], *aliases: str) -> str:
    values = {_header_key(key): _clean_cell(value) for key, value in row.items()}
    for alias in aliases:
        value = values.get(_header_key(alias), "")
        if value:
            return value
    return ""


def _greenbone_patch_available(solution: str, solution_type: str) -> str:
    """Map Greenbone remediation metadata to the canonical patch-available flag.

    Greenbone distinguishes an official vendor fix from workarounds, mitigations,
    and explicit no-fix states.  When a structured solution type is present we
    therefore only report a patch as available for VendorFix.  Older exports may
    omit the type entirely, so retain the historical solution-text fallback for
    those files instead of silently changing their behavior.
    """
    type_key = "".join(ch for ch in _header_key(solution_type) if ch.isalnum())
    if type_key:
        return "1" if type_key == "vendorfix" else "0"
    solution_key = _header_key(solution)
    return "1" if solution_key and solution_key not in {"n a", "none"} else "0"


def _openvas_csv_rows(parsed: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, str]] = []
    source_rows: list[int] = []
    source_errors: list[dict[str, Any]] = []
    parser_warnings: list[str] = []
    for index, raw in enumerate(parsed["rows"]):
        source_row = parsed["source_rows"][index]
        cves = _extract_cves(_row_value(raw, "CVEs", "CVE", "CVE IDs", "Vulnerability IDs"))
        product = _row_value(raw, "NVT Name", "Vulnerability Name", "Name", "Finding")
        hostname = _row_value(raw, "Hostname", "Host Name", "DNS Name")
        host_value = _row_value(raw, "IP", "IP Address", "Host IP", "Host")
        ip_address = _ip_value(host_value)
        if not cves:
            source_errors.append({
                "row_number": source_row,
                "message": "CVE가 없는 OpenVAS 결과는 현재 데이터 모델에 넣을 수 없습니다.",
                "raw": {"host": hostname or host_value, "name": product},
            })
            continue
        if not hostname and not host_value:
            parser_warnings.append(f"행 {source_row}: 자산 식별자가 없습니다.")
        solution = _row_value(raw, "Solution")
        solution_type = _row_value(raw, "Solution Type", "SolutionType")
        notes = _truncate_notes([
            _row_value(raw, "Summary"),
            _row_value(raw, "Specific Result", "Result"),
            _row_value(raw, "Impact"),
            f"해결 방법: {solution}" if solution else "",
            f"포트: {_row_value(raw, 'Port')}" if _row_value(raw, "Port") else "",
        ])
        for cve in cves:
            rows.append({
                "product": product or "OpenVAS finding",
                "cve_id": cve,
                "asset_name": hostname or host_value,
                "ip_address": ip_address,
                "fqdn": _fqdn_value(hostname),
                "component": product,
                "cvss": _row_value(raw, "CVSS", "CVSS Base", "CVSS Base Score", "Severity"),
                "patch_available": _greenbone_patch_available(solution, solution_type),
                "notes": notes,
            })
            source_rows.append(source_row)
            if len(rows) > MAX_CSV_ROWS:
                raise ValueError(f"CVE 확장 결과는 최대 {MAX_CSV_ROWS:,}건까지 지원합니다.")
    return {
        "headers": list(CANONICAL_FIELD_NAMES),
        "rows": rows,
        "source_rows": source_rows,
        "source_errors": source_errors,
        "parser_warnings": list(dict.fromkeys(parser_warnings)),
        "metadata": parsed.get("metadata", {}) | {
            "adapter_profile": "greenbone-csv",
            "result_count": len(parsed["rows"]),
        },
    }


def _openvas_xml_rows(content: bytes) -> dict[str, Any]:
    root, xml_metadata = _safe_xml_document(content)
    results = _children_by_name(root, "result")
    if not results:
        raise ValueError("OpenVAS/Greenbone 보고서에서 result 항목을 찾지 못했습니다.")
    rows: list[dict[str, str]] = []
    source_rows: list[int] = []
    source_errors: list[dict[str, Any]] = []
    parser_warnings: list[str] = []
    attribute_ref_results = 0
    for result_index, result in enumerate(results, start=1):
        host_element = next((child for child in result if _local_name(child.tag) == "host"), None)
        host_text = str(host_element.text or "").strip() if host_element is not None else ""
        if not host_text:
            host_text = _first_text(host_element, "ip")
        hostname = _first_text(host_element, "hostname")
        nvt = next((child for child in result if _local_name(child.tag) == "nvt"), None)
        nvt_name = _first_text(nvt, "name")
        cves = list(dict.fromkeys(_reference_cves(nvt) + _extract_cves(_first_text(result, "cve"))))
        if nvt is not None and any(
            _local_name(child.tag) == "ref" and _extract_cves(child.attrib.get("id"), child.attrib.get("name"))
            for child in nvt.iter()
        ):
            attribute_ref_results += 1
        description = _first_text(result, "description")
        solution = _first_text(nvt, "solution") or _first_text(result, "solution")
        solution_element = next(
            (child for child in (nvt.iter() if nvt is not None else []) if _local_name(child.tag) == "solution"),
            None,
        )
        solution_type = str(solution_element.attrib.get("type") or "").strip() if solution_element is not None else ""
        cvss = _first_text(nvt, "cvss_base", "cvss3_base", "cvss_base_score") or _first_text(result, "severity")
        if not cves:
            source_errors.append({
                "row_number": result_index,
                "message": "CVE가 없는 OpenVAS 결과는 현재 데이터 모델에 넣을 수 없습니다.",
                "raw": {"host": hostname or host_text, "name": nvt_name or _first_text(result, "name")},
            })
            continue
        if not hostname and not host_text:
            parser_warnings.append(f"result {result_index}: 자산 식별자가 없습니다.")
        product = nvt_name or _first_text(result, "name") or "OpenVAS finding"
        port = _first_text(result, "port")
        notes = _truncate_notes([
            description,
            f"해결 방법: {solution}" if solution else "",
            f"포트: {port}" if port else "",
        ])
        for cve in cves:
            rows.append({
                "product": product,
                "cve_id": cve,
                "asset_name": hostname or host_text,
                "ip_address": _ip_value(host_text),
                "fqdn": _fqdn_value(hostname),
                "component": product,
                "cvss": cvss,
                "patch_available": _greenbone_patch_available(solution, solution_type),
                "notes": notes,
            })
            source_rows.append(result_index)
            if len(rows) > MAX_CSV_ROWS:
                raise ValueError(f"CVE 확장 결과는 최대 {MAX_CSV_ROWS:,}건까지 지원합니다.")
    return {
        "headers": list(CANONICAL_FIELD_NAMES),
        "rows": rows,
        "source_rows": source_rows,
        "source_errors": source_errors,
        "parser_warnings": list(dict.fromkeys(parser_warnings)),
        "metadata": {
            **xml_metadata,
            "adapter_profile": "greenbone-xml",
            "result_count": len(results),
            "attribute_ref_results": attribute_ref_results,
        },
    }


__all__ = ["_greenbone_patch_available", "_openvas_csv_rows", "_openvas_xml_rows", "_row_value"]
