from __future__ import annotations

import json
import sqlite3

import pytest

from app.core.storage import apply_import_batch, init_db, list_findings
from app.repositories.reconciliation import canonical_key_for
import app.main as main
from app.services.scanner_compatibility_evaluation import evaluate_scanner_file


def _normalized(payload: dict) -> dict:
    result = main.normalize_row(payload, 0, scanner_source="cvless-test")
    return result if isinstance(result, dict) else payload


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_blank_cve_is_allowed_but_malformed_nonblank_cve_is_rejected():
    payload = {
        "finding_id": "CVL-REQ-1",
        "product": "TLS weak certificate signature",
        "cve_id": "",
        "asset_name": "host.example.test",
        "status": "OPEN",
    }
    normalized = _normalized(dict(payload))
    assert normalized["cve_id"] == ""

    invalid = dict(payload)
    invalid["cve_id"] = "NOT-A-CVE"
    with pytest.raises(ValueError, match="CVE"):
        _normalized(invalid)


def test_cveless_canonical_key_is_semantic_and_ignores_source_result_id():
    base = {
        "product": "TLS weak certificate signature",
        "product_version": "",
        "component": "certificate",
        "component_version": "",
        "cve_id": "",
        "notes": "서비스: https\n포트: 443/tcp",
    }
    first = canonical_key_for({**base, "source_finding_id": "RESULT-A"})
    second = canonical_key_for({**base, "source_finding_id": "RESULT-B"})
    different = canonical_key_for({**base, "product": "TLS obsolete protocol"})
    assert first == second
    assert first != different


def test_nessus_cvless_plugin_is_importable_and_has_source_identity():
    content = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="cvless">
    <ReportHost name="host.example.test">
      <HostProperties>
        <tag name="host-ip">192.0.2.10</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="2"
                  pluginID="900001" pluginName="TLS weak certificate signature"
                  pluginFamily="General">
        <description>Certificate uses a weak signature algorithm.</description>
        <solution>Replace the certificate.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
    evaluation = evaluate_scanner_file(content, filename="cvless.nessus")
    rendered = json.dumps(evaluation, ensure_ascii=False)
    assert "현재 데이터 모델에 넣을 수 없습니다" not in rendered
    assert "유효한 CVE 식별자가 없습니다" not in rendered
    rows = [
        row for row in _walk(evaluation)
        if row.get("product") and "cve_id" in row and "source_finding_id" in row
    ]
    assert any(row.get("cve_id") == "" for row in rows)
    assert any("plugin:900001" in str(row.get("source_finding_id")) for row in rows)


def test_greenbone_cvless_rows_preserve_distinct_result_ids():
    content = (
        "IP,Hostname,Port,Port Protocol,CVSS,NVT Name,CVEs,Result ID,OID,Solution\n"
        "192.0.2.20,gb.example.test,443,tcp,5.0,TLS weak certificate,,"
        "RESULT-A,1.3.6.1.4.1.25623.1.0.900001,Replace certificate\n"
        "192.0.2.20,gb.example.test,443,tcp,5.0,TLS weak certificate,,"
        "RESULT-B,1.3.6.1.4.1.25623.1.0.900001,Replace certificate\n"
    ).encode("utf-8")
    evaluation = evaluate_scanner_file(content, filename="greenbone.csv")
    rendered = json.dumps(evaluation, ensure_ascii=False)
    assert "현재 데이터 모델에 넣을 수 없습니다" not in rendered
    assert "유효한 CVE 식별자가 없습니다" not in rendered
    identities = {
        str(row.get("source_finding_id"))
        for row in _walk(evaluation)
        if row.get("product")
        and row.get("cve_id", None) == ""
        and row.get("source_finding_id")
    }
    assert any("RESULT-A" in value for value in identities)
    assert any("RESULT-B" in value for value in identities)


def test_distinct_source_records_converge_to_one_canonical_finding(tmp_path):
    db = tmp_path / "cvless.sqlite3"
    init_db(db)
    base = {
        "product": "TLS weak certificate",
        "product_version": "",
        "asset_id": "asset-cvless-1",
        "asset_name": "gb.example.test",
        "environment": "prod",
        "cve_id": "",
        "component": "certificate",
        "component_version": "",
        "cvss": 5.0,
        "status": "OPEN",
        "notes": "서비스: https\n포트: 443/tcp",
    }
    first = _normalized(
        {**base, "finding_id": "CVL-SRC-A", "source_finding_id": "RESULT-A"}
    )
    second = _normalized(
        {**base, "finding_id": "CVL-SRC-B", "source_finding_id": "RESULT-B"}
    )

    apply_import_batch(db, [first], scanner_source="greenbone", filename="a.csv")
    apply_import_batch(db, [second], scanner_source="greenbone", filename="b.csv")

    active = [
        row for row in list_findings(db)
        if str(row.get("record_state") or "ACTIVE") != "ARCHIVED"
    ]
    assert len(active) == 1
    assert active[0]["cve_id"] == ""

    with sqlite3.connect(db) as conn:
        source_rows = conn.execute(
            "SELECT source_finding_id,finding_id FROM source_finding_records "
            "WHERE scanner_source='greenbone' ORDER BY source_finding_id"
        ).fetchall()
        assert [row[0] for row in source_rows] == ["RESULT-A", "RESULT-B"]
        assert len({row[1] for row in source_rows}) == 1

        observations = conn.execute(
            "SELECT source_record_id FROM finding_observations "
            "WHERE scanner_source='greenbone' AND observation='PRESENT'"
        ).fetchall()
        assert len(observations) >= 2
        assert all(row[0] for row in observations)
