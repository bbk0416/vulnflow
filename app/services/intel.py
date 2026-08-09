from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlencode

from app.core.database_schema import CURRENT_APP_VERSION
from app.services.outbound_http import OutboundError
from app.services.outbound_json import request_json_with_retries

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = f"VulnFlow/{CURRENT_APP_VERSION} threat-intelligence"
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class IntelligenceError(RuntimeError):
    pass


def _fetch_json(
    url: str,
    *,
    timeout: int,
    retries: int,
    max_response_bytes: int,
    allow_private_networks: bool,
    host_allowlist: str | Iterable[str] | None,
) -> dict[str, Any]:
    result = request_json_with_retries(
        "GET",
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout_seconds=timeout,
        retries=retries,
        max_response_bytes=max_response_bytes,
        allow_private_networks=allow_private_networks,
        host_allowlist=host_allowlist,
    )
    return result.payload


def fetch_kev_catalog(
    timeout: int = 30,
    *,
    retries: int = 3,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
) -> set[str]:
    try:
        payload = _fetch_json(
            KEV_URL,
            timeout=timeout,
            retries=retries,
            max_response_bytes=max_response_bytes,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
        )
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise ValueError("KEV 취약점 목록이 비어 있거나 형식이 올바르지 않습니다.")
        catalog = {
            str(item.get("cveID") or "").strip().upper()
            for item in vulnerabilities
            if isinstance(item, dict) and str(item.get("cveID") or "").upper().startswith("CVE-")
        }
        if not catalog:
            raise ValueError("유효한 CVE 식별자가 없는 KEV 응답입니다.")
        return catalog
    except (OutboundError, ValueError, KeyError, TypeError) as exc:
        raise IntelligenceError(f"CISA KEV 갱신 실패: {exc}") from exc


def fetch_epss(
    cve_ids: Iterable[str],
    timeout: int = 30,
    *,
    retries: int = 3,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
) -> dict[str, dict[str, float]]:
    unique = sorted({
        str(cve).upper() for cve in cve_ids if str(cve).upper().startswith("CVE-")
    })
    output: dict[str, dict[str, float]] = {}
    try:
        for start in range(0, len(unique), 100):
            batch = unique[start:start + 100]
            if not batch:
                continue
            payload = _fetch_json(
                f"{EPSS_URL}?{urlencode({'cve': ','.join(batch)})}",
                timeout=timeout,
                retries=retries,
                max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks,
                host_allowlist=host_allowlist,
            )
            rows = payload.get("data", [])
            if not isinstance(rows, list):
                raise ValueError("EPSS data 필드가 목록이 아닙니다.")
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve = str(row["cve"]).upper()
                output[cve] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
    except (OutboundError, ValueError, KeyError, TypeError) as exc:
        raise IntelligenceError(f"FIRST EPSS 갱신 실패: {exc}") from exc
    return output
