from __future__ import annotations

import json
import os
import smtplib
import subprocess
import sys
from pathlib import Path

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.repositories.collaboration import save_integration
from app.services.integration_crypto import encrypt_secret
from app.services.integration_diagnostics import (
    diagnose_email_connection,
    diagnose_jira_connection,
    diagnose_saved_integration,
)
from app.services.scanner_compatibility import (
    build_scanner_compatibility_report,
    evaluate_scanner_file,
)
from scripts.docker_upgrade_rehearsal import run_host_rehearsal
from scripts.production_validation import run_validation
from scripts.scanner_fixture_matrix import run_matrix
from scripts.scanner_parser_robustness import run_robustness_matrix

ROOT = Path(__file__).resolve().parents[1]
MASTER = "production-validation-master-key-123456789"


class _SMTPBase:
    send_called = False

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self):
        return 250, b"ok"

    def starttls(self, context=None):
        return 220, b"ready"

    def login(self, username, password):
        assert username == "mailer"
        assert password == "smtp-secret"
        return 235, b"authenticated"

    def send_message(self, message):
        type(self).send_called = True
        raise AssertionError("connection diagnostic must not send mail")


def _email_config() -> dict:
    return {
        "host": "smtp.example.com",
        "port": 587,
        "security": "STARTTLS",
        "username": "mailer",
        "from_address": "vulnflow@example.com",
        "recipients": ["security@example.com"],
        "events": ["finding.workflow_changed"],
    }


def _jira_config() -> dict:
    return {
        "base_url": "https://example.atlassian.net",
        "email": "security@example.com",
        "project_key": "SEC",
        "issue_type": "Task",
        "events": ["finding.workflow_changed"],
    }


def test_email_diagnostic_authenticates_without_sending(monkeypatch):
    monkeypatch.setattr(
        "app.services.integration_diagnostics_email.connect_outbound_smtp",
        lambda *args, **kwargs: _SMTPBase(),
    )
    result = diagnose_email_connection(
        _email_config(), {"password": "smtp-secret"}, timeout_seconds=3
    )
    assert result["ok"] is True
    assert result["stage"] == "authenticated"
    assert result["details"]["mail_sent"] is False
    assert _SMTPBase.send_called is False


def test_email_diagnostic_hides_authentication_exception(monkeypatch):
    class Rejected(_SMTPBase):
        def login(self, username, password):
            raise smtplib.SMTPAuthenticationError(535, b"secret server detail")

    monkeypatch.setattr(
        "app.services.integration_diagnostics_email.connect_outbound_smtp",
        lambda *args, **kwargs: Rejected(),
    )
    result = diagnose_email_connection(
        _email_config(), {"password": "smtp-secret"}, timeout_seconds=3
    )
    assert result["ok"] is False
    assert result["stage"] == "authentication"
    rendered = json.dumps(result, ensure_ascii=False)
    assert "smtp-secret" not in rendered
    assert "secret server detail" not in rendered


def test_jira_diagnostic_checks_account_and_project_without_writing(monkeypatch):
    calls: list[str] = []

    class Response:
        status_code = 200

    def fake_request(method, url, **kwargs):
        assert method == "GET"
        calls.append(url)
        assert kwargs["basic_auth"] == ("security@example.com", "jira-token")
        return Response()

    monkeypatch.setattr("app.services.integration_diagnostics_jira.request_outbound", fake_request)
    result = diagnose_jira_connection(
        _jira_config(), {"api_token": "jira-token"}, timeout_seconds=3
    )
    assert result["ok"] is True
    assert result["details"]["write_performed"] is False
    assert calls == [
        "https://example.atlassian.net/rest/api/3/myself",
        "https://example.atlassian.net/rest/api/3/project/SEC",
    ]


def test_saved_integration_diagnostic_decrypts_only_inside_service(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config=_email_config(),
        secret_ciphertext=encrypt_secret({"password": "smtp-secret"}, master_key=MASTER),
        actor="admin",
    )
    monkeypatch.setattr(
        "app.services.integration_diagnostics_email.connect_outbound_smtp",
        lambda *args, **kwargs: _SMTPBase(),
    )
    result = diagnose_saved_integration(
        db, channel="EMAIL", master_key=MASTER, timeout_seconds=3
    )
    assert result["ok"] is True
    assert "smtp-secret" not in json.dumps(result)


def test_scanner_compatibility_reports_ready_and_review_states():
    ready_payload = (
        b"product,cve_id,asset_name,cvss,notes\n"
        b"OpenSSL,CVE-2026-91001,api-1,9.8,Upgrade OpenSSL\n"
    )
    ready_eval = evaluate_scanner_file(ready_payload, filename="ready.csv")
    ready = build_scanner_compatibility_report(ready_eval, filename="ready.csv")
    assert ready["status"] == "READY"
    assert ready["importable_rows"] == 1
    assert ready["field_coverage"]["asset_name"]["percent"] == 100

    review_payload = b"product,cve_id\nOpenSSL,CVE-2026-91002\n"
    review_eval = evaluate_scanner_file(review_payload, filename="review.csv")
    review = build_scanner_compatibility_report(review_eval, filename="review.csv")
    assert review["status"] == "REVIEW"
    assert set(review["missing_recommended_fields"]) == {"asset_name", "cvss", "notes"}


def test_nessus_compatibility_counts_non_cve_plugins_as_unsupported():
    payload = b"""<?xml version='1.0'?>
<NessusClientData_v2><Report name='demo'><ReportHost name='10.0.0.8'>
<ReportItem port='443' pluginID='1' pluginName='TLS issue'><cve>CVE-2026-92001</cve><cvss3_base_score>8.8</cvss3_base_score><solution>Upgrade</solution></ReportItem>
<ReportItem port='0' pluginID='2' pluginName='Inventory only'><synopsis>No CVE</synopsis></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""
    evaluation = evaluate_scanner_file(payload, filename="scan.nessus")
    report = build_scanner_compatibility_report(evaluation, filename="scan.nessus")
    assert report["status"] == "REVIEW"
    assert report["source_items"] == 2
    assert report["importable_rows"] == 1
    assert report["unsupported_source_items"] == 1


def test_scanner_compatibility_cli_writes_json(tmp_path: Path):
    source = tmp_path / "customer.csv"
    source.write_text(
        "product,cve_id,asset_name,cvss,notes\nOpenSSL,CVE-2026-93001,api-1,9.1,Upgrade\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "cp1252"
    result = subprocess.run(
        [sys.executable, "scripts/scanner_compatibility_report.py", str(source), "--json-output", str(output), "--require-ready"],
        cwd=ROOT, text=True, capture_output=True, env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["summary"] == {"files": 1, "ready": 1, "review": 0, "blocked": 0}


def test_schema42_host_upgrade_rehearsal_preserves_data_and_adds_collaboration(tmp_path: Path):
    result = run_host_rehearsal(tmp_path)
    assert result["passed"] is True
    assert result["source_schema_version"] == 42
    assert result["target_schema_version"] == CURRENT_SCHEMA_VERSION == 46
    assert all(item["passed"] for item in result["checks"])


def test_docker_upgrade_rehearsal_cli_host_mode(tmp_path: Path):
    output = tmp_path / "docker-upgrade.json"
    result = subprocess.run(
        [
            sys.executable, "scripts/docker_upgrade_rehearsal.py", "--mode", "host",
            "--work-dir", str(tmp_path / "work"), "--json-output", str(output),
        ],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mode"] == "host"
    assert payload["passed"] is True


def test_import_preview_downloads_compatibility_report(client, tmp_path: Path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "IMPORT_PREVIEW_DIR", tmp_path / "previews")
    token = client.get("/upload").cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
    preview = client.post(
        "/upload/findings/preview",
        data={"csrf_token": token, "format_hint": "auto", "scanner_source": "customer", "import_mode": "incremental"},
        files={"file": ("customer.csv", b"product,cve_id,asset_name,cvss,notes\nOpenSSL,CVE-2026-94001,api-1,9.4,Upgrade\n", "text/csv")},
    )
    assert preview.status_code == 200
    import re
    matched = re.search(r'name="token" value="([A-Za-z0-9_-]+)"', preview.text)
    assert matched
    response = client.post(
        "/upload/findings/compatibility",
        data={
            "csrf_token": token,
            "token": matched.group(1),
            "scanner_source": "customer",
            "import_mode": "incremental",
        },
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    report = response.json()
    assert report["status"] == "READY"
    assert report["importable_rows"] == 1


def test_admin_can_run_saved_email_diagnostic_from_ui(client, monkeypatch):
    import app.main as main
    import app.routers.integrations as integrations_router

    main.APPLICATION_CONTEXT.set("INTEGRATION_SECRET_KEY", MASTER)
    main.APPLICATION_CONTEXT.set("COLLABORATION_TIMEOUT_SECONDS", 3)
    from app.routers import refresh_runtime_dependencies
    refresh_runtime_dependencies(main.APPLICATION_CONTEXT)
    monkeypatch.setattr(
        integrations_router,
        "diagnose_saved_integration",
        lambda *args, **kwargs: {
            "channel": "EMAIL", "ok": True, "stage": "authenticated",
            "message": "SMTP 연결과 인증 점검을 통과했습니다.",
            "elapsed_ms": 7, "details": {"mail_sent": False},
        },
    )
    page = client.get("/integrations")
    token = client.cookies.get(main.CSRF_COOKIE)
    assert page.status_code == 200 and token
    response = client.post("/integrations/email/test", data={"csrf_token": token})
    assert response.status_code == 200
    assert "EMAIL 연결 점검 통과" in response.text
    assert "연결 점검은 이메일을 보내거나 Jira 이슈를 만들지 않습니다" in response.text


def test_collaboration_runtime_settings_are_exported_to_application_context():
    from app.core import settings
    required = {
        "INTEGRATION_SECRET_KEY", "COLLABORATION_INTERVAL_SECONDS",
        "COLLABORATION_TIMEOUT_SECONDS", "COLLABORATION_MAX_ATTEMPTS",
        "COLLABORATION_DUE_SOON_DAYS", "PUBLIC_BASE_URL",
    }
    assert required <= set(settings.__all__)


def test_schema43_backup_validation_rejects_missing_collaboration_table(tmp_path: Path):
    import sqlite3
    import pytest
    from app.services.database_lifecycle import validate_database_file

    db = tmp_path / "broken-schema43.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE collaboration_events")
        conn.commit()
    with pytest.raises(ValueError, match="협업 연동 테이블"):
        validate_database_file(db)


def test_synthetic_scanner_fixture_matrix_matches_contract():
    report = run_matrix(ROOT / "tests" / "fixtures" / "scanners")
    assert report["passed"] is True
    assert report["fixtures"] == 9
    assert {item["filename"] for item in report["results"]} == {
        "generic-korean-cp949.csv", "generic.xlsx", "nessus-basic.nessus",
        "nessus-cpe22.nessus", "openvas-duplicate.xml", "openvas-greenbone.csv",
        "openvas-refs.xml", "openvas-report.xml", "openvas-semicolon.csv",
    }


def test_scanner_fixture_matrix_cli_writes_report(tmp_path: Path):
    output = tmp_path / "fixture-matrix.json"
    result = subprocess.run(
        [sys.executable, "scripts/scanner_fixture_matrix.py", "--json-output", str(output)],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert "not a vendor-version certification" in payload["fixture_scope"]


def test_self_contained_production_validation_passes_without_docker(tmp_path: Path):
    report = run_validation(work_dir=tmp_path, docker_mode="skip")
    assert report["passed"] is True
    checks = {item["name"]: item for item in report["checks"]}
    assert checks["schema42_to_current_host_upgrade"]["passed"] is True
    assert checks["synthetic_scanner_fixture_matrix"]["passed"] is True
    assert checks["scanner_parser_robustness"]["passed"] is True
    assert checks["scanner_anonymization_rehearsal"]["passed"] is True
    assert checks["docker_upgrade_rehearsal"]["passed"] is None


def test_production_validation_cli_writes_json(tmp_path: Path):
    output = tmp_path / "production-validation.json"
    result = subprocess.run(
        [sys.executable, "scripts/production_validation.py", "--docker", "skip",
         "--work-dir", str(tmp_path / "work"), "--json-output", str(output)],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert len(payload["checks"]) == 5



def test_scanner_compatibility_report_flags_duplicate_canonical_rows():
    payload = (ROOT / "tests" / "fixtures" / "scanners" / "openvas-duplicate.xml").read_bytes()
    evaluation = evaluate_scanner_file(payload, filename="openvas-duplicate.xml")
    report = build_scanner_compatibility_report(evaluation, filename="openvas-duplicate.xml")
    assert report["status"] == "REVIEW"
    assert report["duplicate_rows"] == 1
    assert report["warning_count"] == 1
    assert "중복" in report["warnings"][0]
    assert report["parser_contract"]["xml_max_depth"] == 128


def test_scanner_compatibility_cli_rejects_oversized_file_before_read(tmp_path: Path):
    from app.core.settings import MAX_IMPORT_UPLOAD_BYTES

    source = tmp_path / "oversized.nessus"
    with source.open("wb") as handle:
        handle.truncate(MAX_IMPORT_UPLOAD_BYTES + 1)
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "cp1252"
    result = subprocess.run(
        [sys.executable, "scripts/scanner_compatibility_report.py", str(source)],
        cwd=ROOT, text=True, capture_output=True, env=environment,
    )
    assert result.returncode == 2
    assert "최대" in result.stderr or r"\ucd5c\ub300" in result.stderr



def test_scanner_parser_robustness_matrix_passes_all_contracts():
    report = run_robustness_matrix()
    assert report["passed"] is True
    assert len(report["cases"]) == 6
    assert {item["name"] for item in report["cases"]} == {
        "utf8_bom_extensionless_xml",
        "nessus_cpe22_cvss4",
        "duplicate_canonical_rows_review",
        "doctype_entity_blocked",
        "excessive_xml_depth_blocked",
        "truncated_xml_blocked",
    }


def test_scanner_parser_robustness_cli_writes_json(tmp_path: Path):
    output = tmp_path / "scanner-robustness.json"
    result = subprocess.run(
        [sys.executable, "scripts/scanner_parser_robustness.py", "--json-output", str(output)],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert len(payload["cases"]) == 6
