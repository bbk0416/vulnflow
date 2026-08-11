from __future__ import annotations

import io
import re
from pathlib import Path

from fastapi.testclient import TestClient
from openpyxl import Workbook
import pytest

import app.main as main
from app.services.finding_imports import (
    auto_map_headers,
    create_preview_session,
    load_preview_session,
    map_import_rows,
    parse_import_file,
)


def _csrf(client: TestClient) -> str:
    response = client.get("/upload")
    assert response.status_code == 200
    return client.cookies.get(main.CSRF_COOKIE)


def test_cp949_csv_and_korean_header_auto_mapping():
    content = "제품명,CVE,호스트명,IP 주소,CVSS\n웹서버,CVE-2026-12345,server-a,10.0.0.1,9.8\n".encode("cp949")
    parsed = parse_import_file(content, filename="진단결과.csv")
    assert parsed["detected_format"] == "csv"
    assert parsed["metadata"]["encoding"] == "cp949"
    assert parsed["mapping"]["product"] == "제품명"
    assert parsed["mapping"]["cve_id"] == "CVE"
    assert parsed["mapping"]["asset_name"] == "호스트명"

    with pytest.raises(ValueError, match="열 수가 헤더보다 많습니다"):
        parse_import_file(
            b"product,cve_id,asset_name,cvss\nOpenSSL,CVE-2026-12345,host-a,9.8,EXTRA\n",
            filename="ragged.csv",
        )
    with pytest.raises(ValueError, match="CSV 형식 오류"):
        parse_import_file(
            b'product,cve_id,asset_name,notes\nOpenSSL,CVE-2026-12345,host-a,"unterminated\n',
            filename="broken-quotes.csv",
        )


def test_xlsx_first_nonempty_sheet_and_cve_expansion():
    workbook = Workbook()
    empty = workbook.active
    empty.title = "안내"
    sheet = workbook.create_sheet("진단결과")
    sheet.append(["제품", "CVE", "자산명", "CVSS"])
    sheet.append(["OpenSSL", "CVE-2026-11111, CVE-2026-22222", "api-1", 9.1])
    buffer = io.BytesIO()
    workbook.save(buffer)
    parsed = parse_import_file(buffer.getvalue(), filename="result.xlsx")
    assert parsed["detected_format"] == "xlsx"
    assert parsed["metadata"]["sheet_name"] == "진단결과"
    mapped, source_rows, errors = map_import_rows(parsed["rows"], parsed["source_rows"], parsed["mapping"])
    assert errors == []
    assert [row["cve_id"] for row in mapped] == ["CVE-2026-11111", "CVE-2026-22222"]
    assert source_rows == [2, 2]

    overflow = Workbook()
    overflow_sheet = overflow.active
    overflow_sheet.append(["product", "cve_id"])
    overflow_sheet.append(["OpenSSL", "CVE-2026-12345", "EXTRA"])
    overflow_buffer = io.BytesIO()
    overflow.save(overflow_buffer)
    with pytest.raises(ValueError, match="XLSX 행 2의 열 수가 헤더보다 많습니다"):
        parse_import_file(overflow_buffer.getvalue(), filename="ragged.xlsx")


def test_nessus_adapter_extracts_cves_and_reports_non_cve_plugins():
    payload = b"""<?xml version='1.0'?>
<NessusClientData_v2><Report name='demo'><ReportHost name='10.0.0.8'>
<HostProperties><tag name='host-ip'>10.0.0.8</tag><tag name='host-fqdn'>web.example.test</tag></HostProperties>
<ReportItem port='443' svc_name='https' pluginID='1001' pluginName='OpenSSL issue'>
<cve>CVE-2026-30001</cve><cve>CVE-2026-30002</cve><cvss3_base_score>9.8</cvss3_base_score>
<synopsis>Critical TLS issue</synopsis><solution>Upgrade OpenSSL</solution>
</ReportItem>
<ReportItem port='0' svc_name='general' pluginID='1002' pluginName='Informational item'><synopsis>No CVE</synopsis></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""
    parsed = parse_import_file(payload, filename="scan.nessus")
    assert parsed["detected_format"] == "nessus"
    assert len(parsed["rows"]) == 2
    assert len(parsed["source_errors"]) == 1
    assert parsed["rows"][0]["asset_name"] == "web.example.test"
    assert parsed["rows"][0]["patch_available"] == "1"
    mapped, source_rows, errors = map_import_rows(parsed["rows"], parsed["source_rows"], parsed["mapping"])
    assert len(mapped) == 2 and errors == [] and source_rows == [1, 1]


def test_openvas_csv_is_detected_and_mapped():
    content = (
        "IP,Hostname,Port,NVT Name,CVEs,CVSS,Summary\n"
        "10.0.0.9,db-1,5432/tcp,PostgreSQL issue,CVE-2026-44444,8.8,Upgrade required\n"
    ).encode()
    parsed = parse_import_file(content, filename="greenbone.csv")
    assert parsed["detected_format"] == "openvas_csv"
    assert parsed["scanner_source_suggestion"] == "openvas"
    assert parsed["mapping"]["product"] == "product"
    assert parsed["mapping"]["cve_id"] == "cve_id"
    assert parsed["mapping"]["ip_address"] == "ip_address"



def test_openvas_xml_adapter_extracts_result():
    payload = b"""<?xml version='1.0'?><get_reports_response><report><report><results>
    <result id='r1'><name>TLS weakness</name><host>10.0.0.30<hostname>tls.example.test</hostname></host>
    <port>443/tcp</port><nvt oid='1.3.6'><name>TLS weakness</name><cve>CVE-2026-65001</cve><cvss_base>7.5</cvss_base></nvt>
    <description>Upgrade the affected TLS library.</description></result>
    </results></report></report></get_reports_response>"""
    parsed = parse_import_file(payload, filename="report.xml")
    assert parsed["detected_format"] == "openvas_xml"
    assert parsed["rows"][0]["cve_id"] == "CVE-2026-65001"
    assert parsed["rows"][0]["asset_name"] == "tls.example.test"
    assert parsed["rows"][0]["ip_address"] == "10.0.0.30"

def test_preview_session_is_actor_bound(tmp_path: Path):
    token = create_preview_session(
        tmp_path,
        content=b"product,cve_id\nDemo,CVE-2026-55555\n",
        filename="demo.csv",
        format_hint="auto",
        actor="operator-a",
        ttl_seconds=1800,
    )
    metadata, content = load_preview_session(tmp_path, token, actor="operator-a", ttl_seconds=1800)
    assert metadata["filename"] == "demo.csv"
    assert b"CVE-2026-55555" in content
    try:
        load_preview_session(tmp_path, token, actor="operator-b", ttl_seconds=1800)
    except PermissionError:
        pass
    else:
        raise AssertionError("preview session must be actor-bound")


def test_import_preview_and_apply_openvas_csv(client: TestClient, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "IMPORT_PREVIEW_DIR", tmp_path / "previews")
    token = _csrf(client)
    content = (
        "IP,Hostname,NVT Name,CVEs,CVSS,Summary\n"
        "10.0.0.21,app-21,Demo NVT,CVE-2026-61001,9.4,Patch now\n"
    ).encode()
    preview = client.post(
        "/upload/findings/preview",
        data={"csrf_token": token, "format_hint": "auto", "scanner_source": "", "import_mode": "incremental"},
        files={"file": ("openvas.csv", content, "text/csv")},
    )
    assert preview.status_code == 200
    assert "OpenVAS/Greenbone CSV" in preview.text
    assert "반영 가능" in preview.text
    match = re.search(r'name="token" value="([A-Za-z0-9_-]+)"', preview.text)
    assert match
    preview_token = match.group(1)
    apply = client.post(
        "/upload/findings/apply",
        data={
            "csrf_token": token,
            "token": preview_token,
            "scanner_source": "openvas-lab",
            "import_mode": "incremental",
        },
        follow_redirects=False,
    )
    assert apply.status_code == 303
    found = client.get("/api/v1/findings?query=CVE-2026-61001").json()["items"]
    assert len(found) == 1
    assert found[0]["scanner_source"] == "openvas-lab"
    assert found[0]["asset_name"] == "app-21"


def test_invalid_rows_can_be_downloaded_and_explicitly_skipped(client: TestClient, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "IMPORT_PREVIEW_DIR", tmp_path / "previews")
    token = _csrf(client)
    content = (
        "product,cve_id,asset_name,cvss\n"
        "Good,CVE-2026-62001,host-good,8.0\n"
        "Bad,NOT-A-CVE,host-bad,7.0\n"
    ).encode()
    preview = client.post(
        "/upload/findings/preview",
        data={"csrf_token": token, "format_hint": "csv", "scanner_source": "manual", "import_mode": "incremental"},
        files={"file": ("mixed.csv", content, "text/csv")},
    )
    assert preview.status_code == 200
    assert "확인 필요한 항목" in preview.text
    match = re.search(r'name="token" value="([A-Za-z0-9_-]+)"', preview.text)
    assert match
    preview_token = match.group(1)
    common = {
        "csrf_token": token,
        "token": preview_token,
        "scanner_source": "manual",
        "import_mode": "incremental",
    }
    errors = client.post("/upload/findings/errors", data=common)
    assert errors.status_code == 200
    assert errors.content.startswith(b"\xef\xbb\xbf")
    assert b"NOT-A-CVE" in errors.content
    blocked = client.post("/upload/findings/apply", data=common)
    assert blocked.status_code == 400
    applied = client.post(
        "/upload/findings/apply",
        data={**common, "skip_invalid": "1"},
        follow_redirects=False,
    )
    assert applied.status_code == 303
    assert "upload_partial" in applied.headers["location"]
    assert len(client.get("/api/v1/findings?query=CVE-2026-62001").json()["items"]) == 1


def test_snapshot_import_never_skips_invalid_rows(client: TestClient, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "IMPORT_PREVIEW_DIR", tmp_path / "previews")
    token = _csrf(client)
    content = b"product,cve_id\nGood,CVE-2026-63001\nBad,INVALID\n"
    preview = client.post(
        "/upload/findings/preview",
        data={"csrf_token": token, "format_hint": "csv", "scanner_source": "snapshot-test", "import_mode": "snapshot"},
        files={"file": ("snapshot.csv", content, "text/csv")},
    )
    match = re.search(r'name="token" value="([A-Za-z0-9_-]+)"', preview.text)
    assert match
    response = client.post(
        "/upload/findings/apply",
        data={
            "csrf_token": token,
            "token": match.group(1),
            "scanner_source": "snapshot-test",
            "import_mode": "snapshot",
            "skip_invalid": "1",
        },
    )
    assert response.status_code == 400
    assert "전체 결과 대조에서는 오류 행 건너뛰기를 허용하지 않습니다" in response.text



def test_nessus_cpe22_cvss4_and_asset_uuid_are_preserved():
    payload = (Path(__file__).parent / "fixtures" / "scanners" / "nessus-cpe22.nessus").read_bytes()
    parsed = parse_import_file(payload, filename="nessus-cpe22.nessus")
    row = parsed["rows"][0]
    assert row["product"] == "acme widget_server"
    assert row["product_version"] == "1.2.3"
    assert row["cvss"] == "9.3"
    assert row["asset_id"] == "fixture-host-uuid"
    assert parsed["metadata"]["cpe22_items"] == 1
    assert parsed["metadata"]["adapter_profile"] == "nessus-client-data-v2"


def test_openvas_xml_extracts_cve_ref_attributes_and_solution():
    payload = (Path(__file__).parent / "fixtures" / "scanners" / "openvas-refs.xml").read_bytes()
    parsed = parse_import_file(payload, filename="openvas-refs.xml")
    row = parsed["rows"][0]
    assert row["cve_id"] == "CVE-2026-96002"
    assert row["patch_available"] == "1"
    assert "해결 방법" in row["notes"]
    assert parsed["metadata"]["attribute_ref_results"] == 1


def test_extensionless_utf8_bom_openvas_xml_is_detected():
    payload = (Path(__file__).parent / "fixtures" / "scanners" / "openvas-refs.xml").read_bytes()
    parsed = parse_import_file(b"\xef\xbb\xbf" + payload, filename="customer-export")
    assert parsed["detected_format"] == "openvas_xml"
    assert parsed["rows"][0]["cve_id"] == "CVE-2026-96002"


def test_openvas_semicolon_csv_uses_host_as_ip_address():
    payload = (Path(__file__).parent / "fixtures" / "scanners" / "openvas-semicolon.csv").read_bytes()
    parsed = parse_import_file(payload, filename="openvas-semicolon.csv")
    row = parsed["rows"][0]
    assert parsed["detected_format"] == "openvas_csv"
    assert parsed["metadata"]["delimiter"] == ";"
    assert row["asset_name"] == "198.51.100.30"
    assert row["ip_address"] == "198.51.100.30"
    assert row["patch_available"] == "1"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            b"<?xml version='1.0'?><!DOCTYPE report [<!ENTITY x 'boom'>]><report>&x;</report>",
            "DOCTYPE 또는 ENTITY",
        ),
        (
            ("<get_reports_response>" + "<x>" * 129 + "</x>" * 129 + "</get_reports_response>").encode(),
            "중첩 깊이",
        ),
    ],
)
def test_scanner_xml_structural_guards_block_unsafe_documents(payload: bytes, message: str):
    with pytest.raises(ValueError, match=message):
        parse_import_file(payload, filename="unsafe.xml")


def test_duplicate_scanner_preview_surfaces_parser_warning(client: TestClient, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "IMPORT_PREVIEW_DIR", tmp_path / "previews")
    token = _csrf(client)
    payload = (Path(__file__).parent / "fixtures" / "scanners" / "openvas-duplicate.xml").read_bytes()
    preview = client.post(
        "/upload/findings/preview",
        data={
            "csrf_token": token,
            "format_hint": "auto",
            "scanner_source": "openvas-duplicate",
            "import_mode": "incremental",
        },
        files={"file": ("openvas-duplicate.xml", payload, "application/xml")},
    )
    assert preview.status_code == 200
    assert "스캐너 파일 호환성: REVIEW" in preview.text
    assert "파서 경고" in preview.text
    assert "중복" in preview.text
