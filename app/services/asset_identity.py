from __future__ import annotations

import ipaddress
import re
import unicodedata

import idna
from typing import Any

ASSET_IDENTIFIER_TYPES = {
    "SCANNER_ASSET_ID", "EXTERNAL_ASSET_ID", "INVENTORY_ID", "CMDB_ID", "CLOUD_INSTANCE_ID",
    "FQDN", "HOSTNAME", "IP_ADDRESS", "MAC_ADDRESS",
}
ASSET_IDENTIFIER_STATUSES = {"ACTIVE", "RETIRED"}
ASSET_IDENTITY_CANDIDATE_STATUSES = {"PENDING", "REJECTED", "MERGED"}
AUTHORITATIVE_IDENTIFIER_TYPES = {"SCANNER_ASSET_ID", "INVENTORY_ID", "CMDB_ID", "CLOUD_INSTANCE_ID"}
IDENTIFIER_CONFIDENCE = {
    "SCANNER_ASSET_ID": 100, "EXTERNAL_ASSET_ID": 70, "INVENTORY_ID": 100, "CMDB_ID": 100,
    "CLOUD_INSTANCE_ID": 100, "FQDN": 85, "MAC_ADDRESS": 80,
    "IP_ADDRESS": 70, "HOSTNAME": 50,
}
MAC_ADDRESS_RE = re.compile(r"^[0-9a-fA-F]{2}([:\-]?[0-9a-fA-F]{2}){5}$")


def normalize_asset_identifier(identifier_type: str, value: Any) -> str:
    kind = str(identifier_type or "").strip().upper()
    if kind not in ASSET_IDENTIFIER_TYPES:
        raise ValueError(f"허용되지 않은 자산 식별자 유형: {kind}")
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("자산 식별자 값이 필요합니다.")
    if len(raw) > 500:
        raise ValueError("자산 식별자 값은 500자 이하여야 합니다.")
    if kind == "IP_ADDRESS":
        candidate = raw[1:-1].strip() if raw.startswith("[") and raw.endswith("]") else raw
        try:
            return ipaddress.ip_address(candidate).compressed.casefold()
        except ValueError as exc:
            raise ValueError(f"IP 주소 형식이 올바르지 않습니다: {raw}") from exc
    if kind == "MAC_ADDRESS":
        if not MAC_ADDRESS_RE.fullmatch(raw):
            raise ValueError(f"MAC 주소 형식이 올바르지 않습니다: {raw}")
        compact = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    if kind == "FQDN":
        if raw.endswith(".."):
            raise ValueError(f"FQDN 형식이 올바르지 않습니다: {raw}")
        domain = raw[:-1] if raw.endswith(".") else raw
        if "." not in domain or any(char.isspace() or ord(char) < 32 or char in "/\\[]:@" for char in domain):
            raise ValueError(f"FQDN 형식이 올바르지 않습니다: {raw}")
        try:
            ascii_name = idna.encode(
                domain, uts46=True, std3_rules=True, transitional=False
            ).decode("ascii").lower()
        except idna.IDNAError as exc:
            raise ValueError(f"FQDN 형식이 올바르지 않습니다: {raw}") from exc
        if len(ascii_name) > 253:
            raise ValueError(f"FQDN 형식이 올바르지 않습니다: {raw}")
        try:
            ipaddress.ip_address(ascii_name)
        except ValueError:
            pass
        else:
            raise ValueError(f"FQDN 형식이 올바르지 않습니다: {raw}")
        return ascii_name
    return raw.casefold()


def fqdn_equivalent_values(value: Any) -> tuple[str, ...]:
    """Return the canonical IDNA2008 A-label plus its stable Unicode U-label.

    The A-label is authoritative for identity. The U-label is retained only as a
    compatibility lookup value for rows written by releases before 72.0.78.
    """
    ascii_name = normalize_asset_identifier("FQDN", value)
    values = [ascii_name]
    try:
        unicode_name = idna.decode(ascii_name, uts46=True, std3_rules=True)
        roundtrip = idna.encode(
            unicode_name, uts46=True, std3_rules=True, transitional=False
        ).decode("ascii").lower()
    except idna.IDNAError:
        return tuple(values)
    if roundtrip == ascii_name and unicode_name not in values:
        values.append(unicode_name)
    return tuple(values)


def identifier_scope(identifier_type: str, *, scanner_source: str = "", environment: str = "") -> str:
    kind = str(identifier_type).upper()
    if kind == "SCANNER_ASSET_ID":
        return "scanner:" + (unicodedata.normalize("NFC", str(scanner_source or "manual").strip()).casefold() or "manual")
    if kind == "HOSTNAME":
        env = str(environment or "").strip().casefold()
        return "environment:" + (env or "unspecified")
    return "global"


def append_identifier(items: list[dict[str, Any]], kind: str, value: Any, *, scanner_source: str,
                      environment: str, source: str) -> None:
    raw = str(value or "").strip()
    if not raw:
        return
    normalized = normalize_asset_identifier(kind, raw)
    scope = identifier_scope(kind, scanner_source=scanner_source, environment=environment)
    key = (kind, scope, normalized)
    if any((item["identifier_type"], item["scope"], item["normalized_value"]) == key for item in items):
        return
    items.append({
        "identifier_type": kind, "scope": scope, "normalized_value": normalized,
        "display_value": raw, "source": source,
        "confidence": IDENTIFIER_CONFIDENCE[kind],
    })


def extract_asset_identifiers(row: dict[str, Any], *, scanner_source: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    environment = str(row.get("environment") or "")
    append_identifier(items, "SCANNER_ASSET_ID", row.get("asset_id"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "EXTERNAL_ASSET_ID", row.get("asset_id"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "CMDB_ID", row.get("cmdb_id"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "CLOUD_INSTANCE_ID", row.get("cloud_instance_id"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "FQDN", row.get("fqdn"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "IP_ADDRESS", row.get("ip_address"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    append_identifier(items, "MAC_ADDRESS", row.get("mac_address"), scanner_source=scanner_source,
                      environment=environment, source=f"scanner:{scanner_source}")
    name = str(row.get("asset_name") or "").strip()
    if name:
        try:
            normalize_asset_identifier("IP_ADDRESS", name)
            append_identifier(items, "IP_ADDRESS", name, scanner_source=scanner_source,
                              environment=environment, source=f"scanner:{scanner_source}")
        except ValueError:
            if "." in name:
                try:
                    append_identifier(items, "FQDN", name, scanner_source=scanner_source,
                                      environment=environment, source=f"scanner:{scanner_source}")
                except ValueError:
                    append_identifier(items, "HOSTNAME", name, scanner_source=scanner_source,
                                      environment=environment, source=f"scanner:{scanner_source}")
            else:
                append_identifier(items, "HOSTNAME", name, scanner_source=scanner_source,
                                  environment=environment, source=f"scanner:{scanner_source}")
    return items
