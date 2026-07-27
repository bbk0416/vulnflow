from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys

import pytest
from pathlib import Path

import app.services.database_lifecycle as database_lifecycle
from app.core.db import connect
from app.core.storage import init_db

ROOT = Path(__file__).resolve().parents[1]


def _run(*parts: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *parts], cwd=ROOT, text=True, capture_output=True)


def test_architecture_review_creates_missing_report_directory(tmp_path: Path) -> None:
    reports = ROOT / "reports"
    shutil.rmtree(reports, ignore_errors=True)
    result = _run("scripts/architecture_review.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (reports / "architecture_review.txt").is_file()
    assert (reports / "architecture_review.json").is_file()


def test_public_submission_readiness_is_self_contained() -> None:
    result = _run("scripts/submission_readiness_smoke.py", "--public")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "public submission readiness verification" in result.stdout


def test_public_manifest_verifier_accepts_repository_manifest() -> None:
    result = _run("scripts/verify_public_manifest.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verification: PASS" in result.stdout


def test_database_validation_closes_sqlite_connection(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "validated.sqlite3"
    init_db(database)
    original_connect = database_lifecycle.sqlite3.connect
    tracked: list[object] = []

    class ConnectionProxy:
        def __init__(self, connection):
            self._connection = connection
            self.closed = False

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def close(self):
            self.closed = True
            return self._connection.close()

    def tracked_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        if not kwargs.get("uri"):
            return connection
        proxy = ConnectionProxy(connection)
        tracked.append(proxy)
        return proxy

    monkeypatch.setattr(database_lifecycle.sqlite3, "connect", tracked_connect)
    summary = database_lifecycle.validate_database_file(database)
    assert summary["schema_version"] >= 1
    assert tracked
    assert all(item.closed for item in tracked)


def test_connect_context_manager_closes_database_handle(tmp_path: Path) -> None:
    database = tmp_path / "context.sqlite3"
    init_db(database)
    with connect(database) as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_clamscan_signature_parser_ignores_windows_drive_colon(tmp_path: Path, monkeypatch) -> None:
    from app.services import evidence as evidence_service

    scanner = tmp_path / "fake-clamscan.exe"
    scanner.write_bytes(b"placeholder")
    evidence = tmp_path / "infected.txt"
    evidence.write_text("sample", encoding="utf-8")

    def fake_run(command, **kwargs):
        output = f"C:\\Temp\\infected.txt: Unit.Test FOUND\n"
        return subprocess.CompletedProcess(command, 1, stdout=output, stderr="")

    monkeypatch.setattr(evidence_service.subprocess, "run", fake_run)
    result = evidence_service.scan_evidence_path(
        evidence, mode="clamscan", clamscan_path=str(scanner)
    )
    assert result["scan_status"] == "INFECTED"
    assert result["scan_signature"] == "Unit.Test"


def test_dashboard_uses_five_primary_navigation_entry_points(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert html.count('class="nav-link') == 2
    assert html.count('class="nav-group') == 3
    for label in ("대시보드", "자산", "조치·승인", "데이터", "운영·설정"):
        assert label in html
    assert 'href="/export/findings.csv"' not in html
    assert 'href="/export/recovery-bundle.zip"' not in html


def test_dashboard_prioritizes_action_queue_and_progressive_filters(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert 'aria-label="오늘의 작업 바로가기"' in html
    assert "오늘 처리할 취약점부터 확인합니다." in html
    assert "즉시 조치" in html
    assert "기한 초과" in html
    assert "조치 검증" in html
    assert "진행 캠페인" in html
    assert '<details class="secondary-metrics">' in html
    assert '<details class="advanced-filters"' in html
    assert '<section class="panel" id="findings">' in html

    filtered = client.get("/?record_state=ALL&page_size=50")
    assert filtered.status_code == 200
    assert '<details class="advanced-filters" open>' in filtered.text

def test_public_ci_runs_one_chromium_browser_workflow_job() -> None:
    workflow = (ROOT / ".github/workflows/public-ci.yml").read_text(encoding="utf-8")
    assert "browser-e2e:" in workflow
    assert 'python-version: "3.13"' in workflow
    assert "requirements-e2e.txt" in workflow
    assert "python -m playwright install --with-deps chromium" in workflow
    assert "python scripts/run_browser_e2e.py" in workflow


def test_browser_e2e_covers_three_primary_vm_flows() -> None:
    browser_test = (ROOT / "tests/e2e/test_vm_workflows.py").read_text(encoding="utf-8")
    for test_name in (
        "test_dashboard_to_finding_workflow_update",
        "test_csv_import_creates_searchable_finding",
        "test_operator_risk_acceptance_requires_approver",
    ):
        assert f"def {test_name}(" in browser_test
