"""Shared canonical fields and normalization helpers for scanner imports."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import date, datetime
from typing import Any

SUPPORTED_IMPORT_FORMATS = {"auto", "csv", "xlsx", "nessus", "openvas"}
CANONICAL_IMPORT_FIELDS: tuple[dict[str, Any], ...] = (
    {"name": "product", "label": "제품·취약점명", "required": True, "group": "essential"},
    {"name": "cve_id", "label": "CVE", "required": True, "group": "essential"},
    {"name": "asset_name", "label": "자산·호스트명", "required": False, "group": "essential"},
    {"name": "ip_address", "label": "IP 주소", "required": False, "group": "essential"},
    {"name": "cvss", "label": "CVSS", "required": False, "group": "essential"},
    {"name": "product_version", "label": "제품 버전", "required": False, "group": "advanced"},
    {"name": "asset_id", "label": "자산 ID", "required": False, "group": "advanced"},
    {"name": "fqdn", "label": "FQDN", "required": False, "group": "advanced"},
    {"name": "environment", "label": "환경", "required": False, "group": "advanced"},
    {"name": "component", "label": "구성요소·플러그인", "required": False, "group": "advanced"},
    {"name": "component_version", "label": "구성요소 버전", "required": False, "group": "advanced"},
    {"name": "epss", "label": "EPSS", "required": False, "group": "advanced"},
    {"name": "epss_percentile", "label": "EPSS percentile", "required": False, "group": "advanced"},
    {"name": "kev", "label": "CISA KEV 여부", "required": False, "group": "advanced"},
    {"name": "internet_exposed", "label": "인터넷 노출", "required": False, "group": "advanced"},
    {"name": "patch_available", "label": "패치·해결책 존재", "required": False, "group": "advanced"},
    {"name": "owner", "label": "담당자", "required": False, "group": "advanced"},
    {"name": "due_date", "label": "목표일", "required": False, "group": "advanced"},
    {"name": "notes", "label": "설명·조치 메모", "required": False, "group": "advanced"},
)
CANONICAL_FIELD_NAMES = tuple(item["name"] for item in CANONICAL_IMPORT_FIELDS)
_HEADER_ALIASES: dict[str, tuple[str, ...]] = {
    "product": (
        "product", "product name", "plugin name", "pluginname", "nvt name", "nvtname",
        "vulnerability", "vulnerability name", "finding", "finding name", "title", "name",
        "service", "service name", "제품", "제품명", "취약점", "취약점명",
    ),
    "cve_id": ("cve_id", "cve id", "cve ids", "cve", "cves", "cve(s)", "cve 목록"),
    "asset_name": (
        "asset_name", "asset name", "asset", "host", "hostname", "host name", "target",
        "computer name", "dns name", "자산", "자산명", "호스트", "호스트명", "대상",
    ),
    "asset_id": ("asset_id", "asset id", "external asset id", "device id", "자산 id"),
    "ip_address": ("ip_address", "ip address", "ip", "host ip", "target ip", "ip 주소"),
    "fqdn": ("fqdn", "fully qualified domain name", "dns", "dns name"),
    "environment": ("environment", "env", "zone", "network", "환경"),
    "product_version": ("product_version", "product version", "version", "제품 버전"),
    "component": (
        "component", "plugin", "plugin name", "nvt", "nvt name", "service", "service name",
        "구성요소", "플러그인",
    ),
    "component_version": ("component_version", "component version", "service version", "구성요소 버전"),
    "cvss": (
        "cvss", "cvss score", "cvss base", "cvss base score", "cvss3 base score",
        "cvss v3", "severity score",
    ),
    "epss": ("epss", "epss score", "epss probability"),
    "epss_percentile": ("epss percentile", "epss_percentile", "epss percentile score"),
    "kev": ("kev", "cisa kev", "known exploited", "known exploited vulnerability"),
    "internet_exposed": ("internet_exposed", "internet exposed", "external", "public", "인터넷 노출"),
    "patch_available": (
        "patch_available", "patch available", "solution available", "fix available", "solution type",
        "패치 여부", "해결책 여부",
    ),
    "owner": ("owner", "assignee", "담당자"),
    "due_date": ("due_date", "due date", "target date", "목표일", "기한"),
    "notes": (
        "notes", "note", "description", "summary", "synopsis", "plugin output", "specific result",
        "result", "solution", "technical details", "설명", "상세", "조치방안", "메모",
    ),
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def _header_key(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
    text = re.sub(r"[_\-./\\]+", " ", text)
    return re.sub(r"\s+", " ", text)

def _clean_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()

def _unique_headers(values: list[Any]) -> list[str]:
    headers: list[str] = []
    used: set[str] = set()
    next_suffix: dict[str, int] = {}
    for index, value in enumerate(values, start=1):
        base = _clean_cell(value) or f"column_{index}"
        candidate = base
        if candidate in used:
            suffix = max(2, next_suffix.get(base, 2))
            while f"{base}_{suffix}" in used:
                suffix += 1
            candidate = f"{base}_{suffix}"
            next_suffix[base] = suffix + 1
        else:
            next_suffix.setdefault(base, 2)
        used.add(candidate)
        headers.append(candidate)
    return headers

def _extract_cves(*values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        for match in _CVE_RE.findall(str(value or "")):
            normalized = match.upper()
            if normalized not in found:
                found.append(normalized)
    return found

def _ip_value(value: Any) -> str:
    text = _clean_cell(value)
    if not text:
        return ""
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return ""


def _fqdn_value(value: str) -> str:
    text = str(value or "").strip()
    if not text or "." not in text or " " in text or _ip_value(text):
        return ""
    return text

def _truncate_notes(parts: list[str], limit: int = 4000) -> str:
    text = "\n\n".join(part.strip() for part in parts if part and part.strip())
    return text[:limit]

