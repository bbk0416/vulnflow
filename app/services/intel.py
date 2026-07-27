from __future__ import annotations

from typing import Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "VulnFlow/16.0 local-vulnerability-operations"


class IntelligenceError(RuntimeError):
    pass


def _session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.4, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET",))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session


def fetch_kev_catalog(timeout: int = 30) -> set[str]:
    try:
        with _session() as session:
            response = session.get(KEV_URL, timeout=timeout)
            response.raise_for_status()
            payload = response.json()
        return {
            str(item["cveID"]).upper()
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        }
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise IntelligenceError(f"CISA KEV 갱신 실패: {exc}") from exc


def fetch_epss(cve_ids: Iterable[str], timeout: int = 30) -> dict[str, dict[str, float]]:
    unique = sorted({str(cve).upper() for cve in cve_ids if str(cve).upper().startswith("CVE-")})
    output: dict[str, dict[str, float]] = {}
    try:
        with _session() as session:
            for start in range(0, len(unique), 100):
                batch = unique[start:start + 100]
                if not batch:
                    continue
                response = session.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout)
                response.raise_for_status()
                payload = response.json()
                for row in payload.get("data", []):
                    output[str(row["cve"]).upper()] = {
                        "epss": float(row["epss"]),
                        "percentile": float(row["percentile"]),
                    }
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise IntelligenceError(f"FIRST EPSS 갱신 실패: {exc}") from exc
    return output
