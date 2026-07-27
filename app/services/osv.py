from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote, urlparse

import requests

from app.core.database_schema import CURRENT_APP_VERSION

DEFAULT_API_BASE = "https://api.osv.dev"
MAX_BATCH_SIZE = 200
MAX_PAGES = 20


class OsvError(RuntimeError):
    pass


def validate_api_base(api_base: str) -> str:
    raw = str(api_base or DEFAULT_API_BASE).strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme == "https" and parsed.netloc:
        return raw
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return raw
    raise OsvError("OSV API base must use HTTPS; loopback HTTP is allowed for local testing")


@dataclass(frozen=True)
class ComponentQuery:
    component_id: str
    purl: str
    version: str
    query: dict[str, Any]


def _strip_purl_version(purl: str) -> str:
    raw = str(purl or "").strip()
    if not raw:
        return ""
    suffix = ""
    base = raw
    for marker in ("?", "#"):
        if marker in base:
            before, after = base.split(marker, 1)
            base = before
            suffix = marker + after + suffix
    if "@" in base:
        base = base.rsplit("@", 1)[0]
    return base + suffix


def _purl_has_version(purl: str) -> bool:
    base = str(purl or "").split("?", 1)[0].split("#", 1)[0]
    return "@" in base


def build_component_query(component: dict[str, Any]) -> ComponentQuery | None:
    component_id = str(component.get("component_id") or "").strip()
    purl = str(component.get("purl") or "").strip()
    version = str(component.get("version") or "").strip()
    if not component_id or not purl:
        return None
    if _purl_has_version(purl):
        query = {"package": {"purl": purl}}
    elif version:
        query = {"package": {"purl": _strip_purl_version(purl)}, "version": version}
    else:
        return None
    return ComponentQuery(component_id=component_id, purl=purl, version=version, query=query)


def _request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: int,
    retries: int,
    json_payload: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    attempts = 0
    last_error: Exception | None = None
    while attempts < max(1, retries):
        attempts += 1
        try:
            response = session.request(
                method,
                url,
                json=json_payload,
                timeout=timeout,
                allow_redirects=False,
                headers={"Accept": "application/json", "User-Agent": f"VulnFlow/{CURRENT_APP_VERSION}"},
            )
            if 300 <= response.status_code < 400:
                raise OsvError("OSV API redirect responses are not accepted")
            if response.status_code in {429, 500, 502, 503, 504} and attempts < retries:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    delay = min(5.0, max(0.1, float(retry_after))) if retry_after else min(0.25 * (2 ** (attempts - 1)), 2.0)
                except ValueError:
                    delay = min(0.25 * (2 ** (attempts - 1)), 2.0)
                time.sleep(delay)
                continue
            if response.status_code != 200:
                raise OsvError(f"OSV API returned HTTP {response.status_code}")
            payload = response.json()
            if not isinstance(payload, dict):
                raise OsvError("OSV API response must be a JSON object")
            return payload, attempts
        except (requests.RequestException, ValueError, OsvError) as exc:
            last_error = exc
            if attempts >= retries:
                break
            time.sleep(min(0.25 * (2 ** (attempts - 1)), 2.0))
    raise OsvError(str(last_error or "OSV API request failed"))


def query_components(
    components: Iterable[dict[str, Any]],
    *,
    api_base: str = DEFAULT_API_BASE,
    timeout: int = 15,
    retries: int = 3,
    batch_size: int = 100,
    session: requests.Session | None = None,
    cached_records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    component_list = [dict(item) for item in components]
    prepared = [query for item in component_list if (query := build_component_query(item))]
    skipped = len(component_list) - len(prepared)
    own_session = session is None
    session = session or requests.Session()
    base = validate_api_base(api_base)
    batch_size = max(1, min(int(batch_size), MAX_BATCH_SIZE))
    cached_records = cached_records or {}
    api_requests = 0
    result_ids: dict[str, dict[str, str]] = {q.component_id: {} for q in prepared}
    errors: list[str] = []
    try:
        for offset in range(0, len(prepared), batch_size):
            batch = prepared[offset:offset + batch_size]
            pending = [(query, None) for query in batch]
            page_count = 0
            while pending:
                page_count += 1
                if page_count > MAX_PAGES:
                    raise OsvError("OSV pagination exceeded the safety limit")
                payload_queries = []
                for query, token in pending:
                    item = dict(query.query)
                    if token:
                        item["page_token"] = token
                    payload_queries.append(item)
                response, attempts = _request_json(
                    session, "POST", f"{base}/v1/querybatch", timeout=timeout,
                    retries=retries, json_payload={"queries": payload_queries},
                )
                api_requests += attempts
                results = response.get("results")
                if not isinstance(results, list) or len(results) != len(pending):
                    raise OsvError("OSV querybatch result count does not match request count")
                next_pending: list[tuple[ComponentQuery, str | None]] = []
                for (query, _), item in zip(pending, results):
                    if not isinstance(item, dict):
                        errors.append(f"{query.component_id}: invalid result")
                        continue
                    vulns = item.get("vulns", [])
                    if not isinstance(vulns, list):
                        vulns = []
                    for vuln in vulns:
                        if not isinstance(vuln, dict):
                            continue
                        osv_id = str(vuln.get("id") or "").strip()
                        if osv_id:
                            result_ids[query.component_id][osv_id] = str(vuln.get("modified") or "")
                    token = str(item.get("next_page_token") or "").strip()
                    if token:
                        next_pending.append((query, token))
                pending = next_pending

        all_ids = sorted({osv_id for values in result_ids.values() for osv_id in values})
        records: dict[str, dict[str, Any]] = {}
        cache_hits = 0
        for osv_id in all_ids:
            expected_modified = next((values[osv_id] for values in result_ids.values() if osv_id in values), "")
            cached = cached_records.get(osv_id)
            if cached and str(cached.get("modified") or "") == expected_modified and cached.get("raw_record"):
                records[osv_id] = dict(cached["raw_record"])
                cache_hits += 1
                continue
            response, attempts = _request_json(
                session, "GET", f"{base}/v1/vulns/{quote(osv_id, safe='')}",
                timeout=timeout, retries=retries,
            )
            api_requests += attempts
            records[osv_id] = response
        return {
            "queries": prepared,
            "skipped_components": skipped,
            "component_vulnerability_ids": result_ids,
            "records": records,
            "cache_hits": cache_hits,
            "api_requests": api_requests,
            "errors": errors,
        }
    finally:
        if own_session:
            session.close()


def record_digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def cve_aliases(record: dict[str, Any]) -> list[str]:
    aliases = [str(value).upper() for value in record.get("aliases", []) if isinstance(value, str)]
    record_id = str(record.get("id") or "").upper()
    if record_id.startswith("CVE-"):
        aliases.append(record_id)
    return sorted({value for value in aliases if value.startswith("CVE-")})


def fixed_versions(record: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for affected in record.get("affected", []) if isinstance(record.get("affected"), list) else []:
        if not isinstance(affected, dict):
            continue
        for value in affected.get("versions", []) if isinstance(affected.get("versions"), list) else []:
            # affected.versions are vulnerable versions, not fixes; intentionally ignored.
            _ = value
        for range_item in affected.get("ranges", []) if isinstance(affected.get("ranges"), list) else []:
            if not isinstance(range_item, dict):
                continue
            for event in range_item.get("events", []) if isinstance(range_item.get("events"), list) else []:
                if isinstance(event, dict) and str(event.get("fixed") or "").strip():
                    output.append(str(event["fixed"]).strip())
    return sorted(set(output))


def severity_summary(record: dict[str, Any]) -> tuple[str, str, float]:
    label = ""
    vector = ""
    numeric = 0.0
    severity = record.get("severity", [])
    if isinstance(severity, list):
        for item in severity:
            if not isinstance(item, dict):
                continue
            score = str(item.get("score") or "").strip()
            kind = str(item.get("type") or "").strip().upper()
            if kind.startswith("CVSS") and score:
                vector = score
                break
    for affected in record.get("affected", []) if isinstance(record.get("affected"), list) else []:
        if not isinstance(affected, dict):
            continue
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if isinstance(container, dict) and str(container.get("severity") or "").strip():
                label = str(container["severity"]).strip().upper()
                break
        if label:
            break
    if not label and isinstance(record.get("database_specific"), dict):
        label = str(record["database_specific"].get("severity") or "").strip().upper()
    numeric = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}.get(label, 0.0)
    return label, vector, numeric
