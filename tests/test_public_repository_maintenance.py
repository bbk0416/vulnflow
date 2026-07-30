from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys

import pytest
from pathlib import Path

import app.services.database_lifecycle as database_lifecycle
from scripts import release_metadata
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

    dependency_lock = _run("scripts/dependency_lock.py")
    assert dependency_lock.returncode == 0, dependency_lock.stdout + dependency_lock.stderr
    assert "dependency lock consistency passed" in dependency_lock.stdout

    release_metadata = _run("scripts/release_metadata.py", "--check", "--public")
    assert release_metadata.returncode == 0, release_metadata.stdout + release_metadata.stderr
    assert "release metadata consistency passed" in release_metadata.stdout


def test_release_metadata_missing_manifest_respects_collect_tests_flag(
    tmp_path: Path, monkeypatch
) -> None:
    observed: list[bool] = []

    def fake_default_manifest(root: Path, *, collect_tests: bool = True):
        observed.append(collect_tests)
        return {"tests": {"passed": 0, "files": 0}}

    monkeypatch.setattr(release_metadata, "default_manifest", fake_default_manifest)
    manifest = release_metadata.load_manifest(tmp_path, collect_tests=False)
    assert manifest["tests"] == {"passed": 0, "files": 0}
    assert observed == [False]


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


def test_readme_presents_three_step_scenario_with_five_screenshots() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## 3단계 시연 시나리오" in readme
    for filename in (
        "dashboard.png",
        "finding-detail.png",
        "asset-inventory.png",
        "data-import.png",
        "risk-approvals.png",
    ):
        assert f"assets/screenshots/{filename}" in readme
        assert (ROOT / "assets/screenshots" / filename).is_file()
    capture = (ROOT / "scripts/capture_public_screenshots.py").read_text(encoding="utf-8")
    assert "public screenshot capture: PASS" in capture
    assert "TemporaryDirectory" in capture


def test_public_ci_runs_static_quality_and_dependency_gate() -> None:
    workflow = (ROOT / ".github/workflows/public-ci.yml").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements-quality.txt").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/run_quality_gates.py").read_text(encoding="utf-8")
    dependency_lock = (ROOT / "scripts/dependency_lock.py").read_text(encoding="utf-8")
    dependency_smoke = (ROOT / "scripts/dependency_lock_smoke.py").read_text(encoding="utf-8")
    assert "quality-gates:" in workflow
    assert "python scripts/run_quality_gates.py" in workflow
    assert "pip install -r requirements-dev.lock" in workflow
    assert "python scripts/dependency_lock_smoke.py" in workflow
    assert "python scripts/release_metadata.py --check --public" in workflow
    assert ".github/workflows/public-ci.yml" in dependency_lock
    assert "tests.yml" not in dependency_lock
    assert "tests.yml" not in dependency_smoke
    for package in ("ruff==", "bandit==", "pip-audit=="):
        assert package in requirements
    for marker in ("ruff-fatal", "bandit-high", "pip-audit"):
        assert marker in runner


def test_database_restore_validation_is_split_into_bounded_helpers() -> None:
    lifecycle = (ROOT / "app/services/database_lifecycle.py").read_text(encoding="utf-8")
    validation = (ROOT / "app/services/database_validation.py").read_text(encoding="utf-8")
    assert "validate_schema_contents" in lifecycle
    assert "def _validate_schema_v18_to_v31" in validation
    assert "def _validate_schema_v39_to_v40" in validation
    assert lifecycle.count("if schema_version >=") == 1

