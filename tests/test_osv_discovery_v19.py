import io
import json
import sqlite3
from pathlib import Path

import pytest

from app.core.storage import CURRENT_SCHEMA_VERSION, init_db, list_findings
from app.services.osv import build_component_query, query_components
from app.services.sbom import (
    SbomError,
    decide_osv_match,
    get_sbom_document,
    list_osv_matches,
    list_osv_scans,
    parse_cyclonedx_json,
    run_osv_scan,
    store_cyclonedx_document,
)


class FakeResponse:
    def __init__(self, status_code, payload, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, record):
        self.record = record
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if url.endswith("/v1/querybatch"):
            queries = kwargs["json"]["queries"]
            return FakeResponse(200, {"results": [{"vulns": [{"id": self.record["id"], "modified": self.record["modified"]}]} for _ in queries]})
        if "/v1/vulns/" in url:
            return FakeResponse(200, self.record)
        raise AssertionError(url)

    def close(self):
        pass


def sbom_payload(*, purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", version="2.14.1"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "application", "name": "Portal", "version": "1.0"}},
        "components": [{
            "type": "library", "bom-ref": purl, "name": "log4j-core", "version": version, "purl": purl,
        }],
    }


def parsed_sbom():
    return parse_cyclonedx_json(io.BytesIO(json.dumps(sbom_payload()).encode()))


def osv_record():
    return {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2025-01-01T00:00:00Z",
        "published": "2021-12-10T00:00:00Z",
        "summary": "Log4Shell remote code execution",
        "details": "Affected versions of log4j-core.",
        "aliases": ["CVE-2021-44228"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.0"}]}],
            "ecosystem_specific": {"severity": "CRITICAL"},
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
    }


def test_schema_v19_has_osv_tables(tmp_path: Path):
    db = tmp_path / "v19.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert {"osv_scan_runs", "osv_vulnerability_records", "sbom_osv_matches"} <= tables


def test_component_query_obeys_osv_version_rules():
    versioned = build_component_query({"component_id": "C1", "purl": "pkg:pypi/jinja2@3.1.4", "version": "3.1.4"})
    assert versioned.query == {"package": {"purl": "pkg:pypi/jinja2@3.1.4"}}
    unversioned = build_component_query({"component_id": "C2", "purl": "pkg:pypi/jinja2", "version": "3.1.4"})
    assert unversioned.query == {"package": {"purl": "pkg:pypi/jinja2"}, "version": "3.1.4"}
    assert build_component_query({"component_id": "C3", "purl": "pkg:pypi/jinja2", "version": ""}) is None


def test_osv_query_rejects_redirects():
    class RedirectSession(FakeSession):
        def request(self, method, url, **kwargs):
            return FakeResponse(302, {}, {"Location": "https://evil.invalid"})
    with pytest.raises(Exception, match="redirect"):
        query_components(
            [{"component_id": "C1", "purl": "pkg:pypi/jinja2@3.1.4", "version": "3.1.4"}],
            session=RedirectSession(osv_record()), retries=1,
        )


def test_osv_scan_cache_candidate_and_confirm_finding(tmp_path: Path):
    db = tmp_path / "v19.sqlite3"
    init_db(db)
    item = store_cyclonedx_document(str(db), parsed_sbom(), source_filename="portal.cdx.json", actor="tester")
    first_session = FakeSession(osv_record())
    first = run_osv_scan(
        str(db), item["sbom_id"], actor="operator", api_base="https://api.osv.dev",
        session=first_session, source_job_id="JOB-1",
    )
    assert first["status"] == "SUCCEEDED"
    assert first["vulnerability_matches"] == 1
    assert first["new_candidates"] == 1
    assert any("/v1/vulns/" in url for _, url, _ in first_session.calls)
    matches = list_osv_matches(str(db), sbom_id=item["sbom_id"])
    assert matches[0]["status"] == "CANDIDATE"
    assert matches[0]["cve_id"] == "CVE-2021-44228"
    assert matches[0]["fixed_versions"] == ["2.15.0"]

    second_session = FakeSession(osv_record())
    second = run_osv_scan(
        str(db), item["sbom_id"], actor="operator", api_base="https://api.osv.dev",
        session=second_session, source_job_id="JOB-2",
    )
    assert second["cache_hits"] == 1
    assert not any("/v1/vulns/" in url for _, url, _ in second_session.calls)
    assert len(list_osv_matches(str(db), sbom_id=item["sbom_id"])) == 1

    confirmed = decide_osv_match(str(db), matches[0]["match_id"], decision="CONFIRM", reason="reviewed", actor="operator")
    assert confirmed["status"] == "CONFIRMED"
    assert confirmed["finding_id"].startswith("AUTO-OSV-")
    finding = next(row for row in list_findings(db) if row["finding_id"] == confirmed["finding_id"])
    assert finding["cve_id"] == "CVE-2021-44228"
    assert finding["patch_available"] == 1
    detail = get_sbom_document(str(db), item["sbom_id"])
    assert any(link["finding_id"] == confirmed["finding_id"] and link["status"] == "CONFIRMED" for link in detail["links"])
    assert len(list_osv_scans(str(db), sbom_id=item["sbom_id"])) == 2


def test_osv_candidate_without_cve_cannot_create_finding(tmp_path: Path):
    db = tmp_path / "v19.sqlite3"
    init_db(db)
    item = store_cyclonedx_document(str(db), parsed_sbom(), source_filename="portal.cdx.json", actor="tester")
    record = osv_record() | {"id": "PYSEC-2025-1", "aliases": []}
    run_osv_scan(str(db), item["sbom_id"], actor="operator", api_base="https://api.osv.dev", session=FakeSession(record))
    match = list_osv_matches(str(db), sbom_id=item["sbom_id"])[0]
    with pytest.raises(SbomError, match="CVE alias"):
        decide_osv_match(str(db), match["match_id"], decision="CONFIRM", reason="", actor="operator")
    rejected = decide_osv_match(str(db), match["match_id"], decision="REJECT", reason="not applicable", actor="operator")
    assert rejected["status"] == "REJECTED"


def test_osv_scan_retry_reuses_source_job_id(tmp_path: Path):
    db = tmp_path / "v19.sqlite3"
    init_db(db)
    item = store_cyclonedx_document(str(db), parsed_sbom(), source_filename="portal.cdx.json", actor="tester")
    class FailSession(FakeSession):
        def request(self, method, url, **kwargs):
            raise RuntimeError("network down")
    with pytest.raises(Exception):
        run_osv_scan(str(db), item["sbom_id"], actor="operator", api_base="https://api.osv.dev", session=FailSession(osv_record()), source_job_id="JOB-RETRY", retries=1)
    succeeded = run_osv_scan(str(db), item["sbom_id"], actor="operator", api_base="https://api.osv.dev", session=FakeSession(osv_record()), source_job_id="JOB-RETRY")
    assert succeeded["status"] == "SUCCEEDED"
    assert len([scan for scan in list_osv_scans(str(db), sbom_id=item["sbom_id"]) if scan.get("source_job_id") == "JOB-RETRY"]) == 1


def test_osv_api_base_rejects_remote_plain_http():
    from app.services.osv import validate_api_base
    with pytest.raises(Exception, match="HTTPS"):
        validate_api_base("http://example.com")
    assert validate_api_base("http://127.0.0.1:9999") == "http://127.0.0.1:9999"


def test_osv_querybatch_pagination_preserves_component_query(monkeypatch):
    monkeypatch.setattr("app.services.osv.time.sleep", lambda _: None)
    first = osv_record()
    second = osv_record() | {
        "id": "GHSA-second-page",
        "modified": "2025-02-01T00:00:00Z",
        "aliases": ["CVE-2025-22222"],
    }

    class PagingSession:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith("/v1/querybatch"):
                query = kwargs["json"]["queries"][0]
                assert query["package"]["purl"] == "pkg:pypi/jinja2@3.1.4"
                if "page_token" not in query:
                    return FakeResponse(200, {"results": [{
                        "vulns": [{"id": first["id"], "modified": first["modified"]}],
                        "next_page_token": "page-2",
                    }]})
                assert query["page_token"] == "page-2"
                return FakeResponse(200, {"results": [{
                    "vulns": [{"id": second["id"], "modified": second["modified"]}],
                }]})
            if url.endswith(first["id"]):
                return FakeResponse(200, first)
            if url.endswith(second["id"]):
                return FakeResponse(200, second)
            raise AssertionError(url)

        def close(self):
            pass

    session = PagingSession()
    result = query_components(
        [{"component_id": "C1", "purl": "pkg:pypi/jinja2@3.1.4", "version": "3.1.4"}],
        session=session,
    )
    assert list(result["component_vulnerability_ids"]["C1"]) == [first["id"], second["id"]]
    assert set(result["records"]) == {first["id"], second["id"]}
    batch_calls = [call for call in session.calls if call[1].endswith("/v1/querybatch")]
    assert len(batch_calls) == 2


def test_osv_retries_rate_limit_then_succeeds(monkeypatch):
    monkeypatch.setattr("app.services.osv.time.sleep", lambda _: None)
    record = osv_record()

    class RateLimitSession(FakeSession):
        def __init__(self):
            super().__init__(record)
            self.batch_attempts = 0

        def request(self, method, url, **kwargs):
            if url.endswith("/v1/querybatch"):
                self.batch_attempts += 1
                if self.batch_attempts == 1:
                    return FakeResponse(429, {}, {"Retry-After": "0"})
            return super().request(method, url, **kwargs)

    session = RateLimitSession()
    result = query_components(
        [{"component_id": "C1", "purl": "pkg:pypi/jinja2@3.1.4", "version": "3.1.4"}],
        session=session,
        retries=2,
    )
    assert session.batch_attempts == 2
    assert result["api_requests"] == 3  # two batch attempts plus one record fetch
    assert record["id"] in result["records"]


def test_osv_rejects_querybatch_result_count_mismatch():
    class MismatchSession(FakeSession):
        def request(self, method, url, **kwargs):
            if url.endswith("/v1/querybatch"):
                return FakeResponse(200, {"results": []})
            return super().request(method, url, **kwargs)

    with pytest.raises(Exception, match="result count"):
        query_components(
            [{"component_id": "C1", "purl": "pkg:pypi/jinja2@3.1.4", "version": "3.1.4"}],
            session=MismatchSession(osv_record()),
        )
