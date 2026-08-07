"""Nessus and Greenbone XML anonymization with bounded parsing."""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from app.services.finding_import_xml import _local_name, _safe_xml_document
from app.services.scanner_anonymization_common import AliasVault, classify_identity, safe_scalar

_FREE_TEXT = {"description", "summary", "synopsis", "solution", "plugin_output", "specific_result", "result", "technical_details", "see_also"}
_SAFE_TEXT = {"cve", "cvss_base_score", "cvss3_base_score", "cvss4_base_score", "severity", "risk_factor", "threat", "qod", "port", "oid", "family", "exploit_available", "exploitability_ease", "solution_type"}
_HOST_TAGS = {"host-fqdn", "hostname", "netbios-name", "computer-name"}
_ID_TAGS = {"host-uuid", "bios-uuid", "mcafee-epo-guid", "uuid", "guid"}


def _strict_cpe(value: str, vault: AliasVault) -> str:
    text = str(value or "").strip()
    parts = text.split(":")
    if text.startswith("cpe:2.3:") and len(parts) >= 6:
        parts[3] = vault.alias("product", parts[3] or "vendor")
        parts[4] = vault.alias("component", parts[4] or "product")
        parts[5] = vault.alias("version", parts[5] or "version")
        return ":".join(parts)
    if text.startswith("cpe:/") and len(parts) >= 5:
        parts[2] = vault.alias("product", parts[2] or "vendor")
        parts[3] = vault.alias("component", parts[3] or "product")
        parts[4] = vault.alias("version", parts[4] or "version")
        return ":".join(parts)
    return vault.alias("component", text)


def _redact_text(element: ET.Element, vault: AliasVault) -> None:
    text = str(element.text or "").strip()
    if len(text) >= 4:
        vault.source_tokens.add(text)
    element.text = "Redacted by VulnFlow anonymizer."



def _sanitize_attributes(element: ET.Element, vault: AliasVault, profile: str) -> None:
    tag = _local_name(element.tag)
    for raw_name, raw_value in list(element.attrib.items()):
        name = _local_name(raw_name)
        value = str(raw_value or "").strip()
        if not value:
            continue
        if name in {"host", "hostname", "ip", "ip_address", "address", "target"}:
            element.attrib[raw_name] = vault.alias(classify_identity(value), value)
        elif name in {"uuid", "guid", "asset_id", "host_id"}:
            element.attrib[raw_name] = vault.alias("uuid" if "-" in value else "asset", value)
        elif name in {"email", "user", "username", "owner"}:
            element.attrib[raw_name] = vault.alias("email" if "@" in value else "owner", value)
        elif name in {"href", "url", "uri"}:
            element.attrib[raw_name] = vault.alias("url", value)
        elif name == "id" and tag not in {"ref", "reportitem", "nvt"}:
            element.attrib[raw_name] = vault.alias("uuid" if "-" in value else "asset", value)
        elif name == "name" and tag in {"report", "task", "owner", "target", "scan"}:
            element.attrib[raw_name] = vault.alias("host", value)
        elif not (tag in {"tag", "reporthost"} and name == "name") and name not in {
            "port", "protocol", "severity", "pluginid", "pluginname", "svc_name", "pluginfamily",
            "oid", "type", "creation_time", "modification_time",
        } and not safe_scalar(value):
            element.attrib[raw_name] = "redacted"

def _sanitize_nessus(root: ET.Element, vault: AliasVault, profile: str) -> None:
    for element in root.iter():
        _sanitize_attributes(element, vault, profile)
        name = _local_name(element.tag)
        if name == "reporthost":
            raw = str(element.attrib.get("name") or "").strip()
            if raw:
                element.attrib["name"] = vault.alias(classify_identity(raw), raw)
        elif name == "reportitem":
            if profile == "strict" and element.attrib.get("pluginName"):
                element.attrib["pluginName"] = vault.alias("component", element.attrib["pluginName"])
            if profile == "strict" and element.attrib.get("svc_name"):
                element.attrib["svc_name"] = vault.alias("component", element.attrib["svc_name"])
        elif name == "tag":
            tag_name = str(element.attrib.get("name") or "").strip().casefold()
            value = str(element.text or "").strip()
            if not value:
                continue
            if tag_name == "host-ip":
                element.text = vault.alias("ip", value)
            elif tag_name in _HOST_TAGS:
                element.text = vault.alias("fqdn" if "." in value else "host", value)
            elif tag_name in _ID_TAGS:
                element.text = vault.alias("uuid", value)
            elif tag_name == "mac-address":
                element.text = vault.alias("mac", value)
            elif tag_name in {"operating-system", "system-type"} and profile == "strict":
                element.text = vault.alias("product", value)
            elif not safe_scalar(value):
                _redact_text(element, vault)
        elif name in _FREE_TEXT:
            _redact_text(element, vault)
        elif name == "cpe" and profile == "strict" and element.text:
            element.text = _strict_cpe(element.text, vault)
        elif name == "xref" and element.text:
            cves = re.findall(r"CVE-\d{4}-\d{4,}", element.text, flags=re.IGNORECASE)
            element.text = ",".join(item.upper() for item in cves)
        elif name not in _SAFE_TEXT and name != "cpe" and element.text and not safe_scalar(element.text):
            _redact_text(element, vault)
        if element.tail and element.tail.strip():
            vault.source_tokens.add(element.tail.strip()) if len(element.tail.strip()) >= 4 else None
            element.tail = ""


def _sanitize_openvas(root: ET.Element, vault: AliasVault, profile: str) -> None:
    parents = {child: parent for parent in root.iter() for child in parent}
    for element in root.iter():
        _sanitize_attributes(element, vault, profile)
        name = _local_name(element.tag)
        parent_name = _local_name(parents[element].tag) if element in parents else ""
        value = str(element.text or "").strip()
        if name == "host" and value:
            element.text = vault.alias(classify_identity(value), value)
        elif name in {"hostname", "fqdn"} and value:
            element.text = vault.alias("fqdn" if "." in value else "host", value)
        elif name in {"ip", "ip_address"} and value:
            element.text = vault.alias("ip", value)
        elif name in {"user", "username", "email", "owner"} and value:
            element.text = vault.alias("email" if "@" in value else "owner", value)
        elif name == "name" and parent_name in {"owner", "task", "target", "report", "scan"} and value:
            element.text = vault.alias("host", value)
        elif name in _FREE_TEXT and value:
            _redact_text(element, vault)
        elif name == "ref":
            ref_type = str(element.attrib.get("type") or "").casefold()
            ref_id = str(element.attrib.get("id") or "")
            if ref_type not in {"cve", "cve_id", "cve-id"} and "CVE-" not in ref_id.upper():
                if ref_id:
                    element.attrib["id"] = "redacted-reference"
                if value:
                    element.text = ""
        elif name in {"name", "nvt"} and value:
            if profile == "strict":
                element.text = vault.alias("component", value)
        elif name not in _SAFE_TEXT and value and not safe_scalar(value):
            _redact_text(element, vault)
        if element.tail and element.tail.strip():
            vault.source_tokens.add(element.tail.strip()) if len(element.tail.strip()) >= 4 else None
            element.tail = ""


def sanitize_xml(content: bytes, *, detected_format: str, vault: AliasVault, profile: str) -> tuple[bytes, dict[str, Any]]:
    root, metadata = _safe_xml_document(content)
    if detected_format == "nessus":
        _sanitize_nessus(root, vault, profile)
    else:
        _sanitize_openvas(root, vault, profile)
    payload = ET.tostring(root, encoding="utf-8", xml_declaration=True, short_empty_elements=True)
    return payload, metadata


__all__ = ["sanitize_xml"]
