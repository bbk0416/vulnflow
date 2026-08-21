"""NessusClientData_v2 adapter for finding imports."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from app.core.settings import MAX_CSV_ROWS
from app.services.finding_import_common import CANONICAL_FIELD_NAMES, _ip_value, _truncate_notes
from app.services.finding_import_xml import (
    _children_by_name,
    _first_text,
    _local_name,
    _reference_cves,
    _safe_xml_document,
)


def _split_cpe(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return [unquote(field).replace("\\!", "!").strip() for field in fields]


def _nessus_asset_id(properties: dict[str, str]) -> tuple[str, bool]:
    """Choose a stable Nessus asset identifier without trusting absent SMBIOS UUID sentinels.

    Tenable's ``host-uuid`` is preferred.  ``bios-uuid`` is used only when it
    contains an actual SMBIOS UUID; all-zero/all-FF values mean the UUID is not
    present and must not become an authoritative scanner asset identifier.
    """
    host_uuid = str(properties.get("host-uuid") or "").strip()
    if host_uuid:
        return host_uuid, False
    bios_uuid = str(properties.get("bios-uuid") or "").strip()
    if bios_uuid:
        compact = re.sub(r"[^0-9a-fA-F]", "", bios_uuid).casefold()
        if len(compact) == 32 and (set(compact) == {"0"} or set(compact) == {"f"}):
            return str(properties.get("mcafee-epo-guid") or "").strip(), True
        return bios_uuid, False
    return str(properties.get("mcafee-epo-guid") or "").strip(), False


def _nessus_component_identity(plugin_name: str, service_name: str, port: str, protocol: str) -> str:
    """Preserve per-endpoint Nessus findings in canonical component identity.

    A single Nessus plugin can legitimately emit separate ReportItem elements for
    the same vulnerability on different ports.  Port zero represents a host-level
    result and therefore keeps the historical component value unchanged.
    """
    base = str(plugin_name or service_name or "").strip()
    port_key = str(port or "").strip()
    if not port_key or port_key == "0":
        return base
    protocol_key = str(protocol or "").strip()
    endpoint = "/".join(value for value in (port_key, protocol_key) if value)
    return f"{base} [{endpoint}]" if base else endpoint


def _nessus_patch_available(solution: str, has_patch: str) -> str:
    """Map Tenable patch metadata to the canonical patch-available flag.

    Modern .nessus exports expose a structured ``has_patch`` boolean.  When
    present, that field is authoritative and must not be overridden by generic
    remediation text in ``solution``.  Older exports may omit ``has_patch``;
    retain the historical solution-text fallback for those files.
    """
    structured = str(has_patch or "").strip().casefold()
    if structured:
        if structured in {"true", "1", "yes"}:
            return "1"
        return "0"
    solution_key = str(solution or "").strip().casefold()
    return "1" if solution_key and solution_key not in {"n/a", "none"} else "0"


def _cpe_product_version(value: str) -> tuple[str, str, str]:
    text = str(value or "").strip()
    if not text:
        return "", "", ""
    parts = _split_cpe(text)
    if len(parts) >= 6 and parts[0].casefold() == "cpe" and parts[1] == "2.3":
        vendor, product, version = parts[3], parts[4], parts[5]
    elif len(parts) >= 5 and parts[0].casefold() == "cpe" and parts[1].startswith("/"):
        vendor, product, version = parts[2], parts[3], parts[4]
    else:
        return "", "", ""
    placeholders = {"", "*", "-", "any", "n/a"}
    normalized = tuple("" if item.casefold() in placeholders else item for item in (vendor, product, version))
    return normalized  # type: ignore[return-value]


def _nessus_rows(content: bytes) -> dict[str, Any]:
    root, xml_metadata = _safe_xml_document(content)
    if _local_name(root.tag) != "nessusclientdata_v2":
        raise ValueError("NessusClientData_v2 형식의 .nessus 파일이 아닙니다.")
    rows: list[dict[str, str]] = []
    source_rows: list[int] = []
    source_errors: list[dict[str, Any]] = []
    parser_warnings: list[str] = []
    item_index = host_count = cpe22_count = cpe23_count = 0
    for host in _children_by_name(root, "ReportHost"):
        host_count += 1
        host_name = str(host.attrib.get("name") or "").strip()
        properties: dict[str, str] = {}
        for tag in _children_by_name(host, "tag"):
            name = str(tag.attrib.get("name") or "").strip().casefold()
            if name:
                properties[name] = str(tag.text or "").strip()
        asset_name = properties.get("host-fqdn") or properties.get("netbios-name") or host_name
        raw_host_ip = properties.get("host-ip", "")
        ip_address = _ip_value(raw_host_ip) or _ip_value(host_name)
        if raw_host_ip and not _ip_value(raw_host_ip):
            parser_warnings.append(f"ReportHost {host_count}: host-ip 값이 올바른 IP 주소가 아닙니다.")
        asset_id, ignored_bios_uuid = _nessus_asset_id(properties)
        if ignored_bios_uuid:
            parser_warnings.append(
                f"ReportHost {host_count}: bios-uuid가 SMBIOS 미존재 sentinel이라 자산 ID로 사용하지 않았습니다."
            )
        if not asset_name and not ip_address:
            parser_warnings.append(f"ReportHost {host_count}: 자산 식별자가 없습니다.")
        for item in [child for child in host if _local_name(child.tag) == "reportitem"]:
            item_index += 1
            cves = _reference_cves(item)
            plugin_name = str(item.attrib.get("pluginName") or "").strip() or _first_text(item, "plugin_name")
            service_name = str(item.attrib.get("svc_name") or "").strip()
            vendor = product_name = product_version = ""
            for cpe in [str(value.text or "").strip() for value in _children_by_name(item, "cpe")]:
                parsed_vendor, parsed_product, parsed_version = _cpe_product_version(cpe)
                if parsed_product:
                    vendor, product_name, product_version = parsed_vendor, parsed_product, parsed_version
                    cpe23_count += int(cpe.startswith("cpe:2.3:"))
                    cpe22_count += int(cpe.startswith("cpe:/"))
                    break
            product = " ".join(value for value in (vendor, product_name) if value) or plugin_name or service_name
            cvss = _first_text(item, "cvss4_base_score", "cvss3_base_score", "cvss_base_score")
            if len(cves) > 1 and cvss:
                parser_warnings.append(
                    f"ReportItem {item_index}: 다중-CVE Nessus plugin의 CVSS 대표 CVE를 식별할 수 없어 CVE별 CVSS를 비웁니다."
                )
                cvss = ""
            solution = _first_text(item, "solution")
            has_patch = _first_text(item, "has_patch")
            normalized_has_patch = has_patch.strip().casefold()
            if normalized_has_patch and normalized_has_patch not in {"true", "false", "1", "0", "yes", "no"}:
                parser_warnings.append(
                    f"ReportItem {item_index}: has_patch boolean 값이 올바르지 않아 패치 없음으로 처리했습니다."
                )
            port = str(item.attrib.get("port") or "").strip()
            protocol = str(item.attrib.get("protocol") or "").strip()
            endpoint = "/".join(value for value in (port, protocol) if value and value != "0")
            component = _nessus_component_identity(plugin_name, service_name, port, protocol)
            notes = _truncate_notes([
                _first_text(item, "synopsis"),
                _first_text(item, "description"),
                f"해결 방법: {solution}" if solution else "",
                _first_text(item, "plugin_output"),
                f"서비스: {service_name}" if service_name else "",
                f"포트: {endpoint}" if endpoint else "",
            ])
            if not cves:
                source_errors.append({
                    "row_number": item_index,
                    "message": "CVE가 없는 Nessus 플러그인 결과는 현재 데이터 모델에 넣을 수 없습니다.",
                    "raw": {"host": asset_name, "plugin": plugin_name, "plugin_id": item.attrib.get("pluginID", "")},
                })
                continue
            for cve in cves:
                rows.append({
                    "product": product,
                    "product_version": product_version,
                    "cve_id": cve,
                    "asset_name": asset_name or ip_address,
                    "asset_id": asset_id,
                    "ip_address": ip_address,
                    "fqdn": properties.get("host-fqdn", ""),
                    "component": component,
                    "cvss": cvss,
                    "patch_available": _nessus_patch_available(solution, has_patch),
                    "notes": notes,
                })
                source_rows.append(item_index)
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
            "adapter_profile": "nessus-client-data-v2",
            "report_hosts": host_count,
            "report_items": item_index,
            "cpe22_items": cpe22_count,
            "cpe23_items": cpe23_count,
        },
    }


__all__ = ["_cpe_product_version", "_nessus_asset_id", "_nessus_patch_available", "_nessus_rows"]
