from __future__ import annotations

import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Iterator
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from playwright.sync_api import Browser, Page, expect, sync_playwright

from app.core.database_schema import init_db
from app.services.accounts import create_user

ROOT = Path(__file__).resolve().parents[2]
ADMIN = {"username": "admin-e2e", "password": "Admin-E2E-Password-42!"}
OPERATOR = {"username": "operator-e2e", "password": "Operator-E2E-Password-42!"}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str, process: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + 30
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"VulnFlow exited before readiness (code={process.returncode}).\n{output}")
        try:
            with urlopen(f"{base_url}/health/live", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, URLError) as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(f"VulnFlow did not become ready: {last_error}")


@pytest.fixture()
def live_server(tmp_path: Path) -> Iterator[str]:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    data_dir = tmp_path / "data"
    db_path = data_dir / "vulnflow.db"
    init_db(db_path)
    create_user(db_path, username=ADMIN["username"], password=ADMIN["password"], role="admin", actor="e2e-bootstrap")
    create_user(db_path, username=OPERATOR["username"], password=OPERATOR["password"], role="operator", actor="e2e-bootstrap")
    env = os.environ.copy()
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "VULNFLOW_BASE_DIR": str(ROOT),
            "VULNFLOW_DATA_DIR": str(data_dir),
            "VULNFLOW_DB": str(db_path),
            "VULNFLOW_EVIDENCE_DIR": str(data_dir / "evidence"),
            "VULNFLOW_EXPORT_DIR": str(data_dir / "exports"),
            "VULNFLOW_RECOVERY_DIR": str(data_dir / "recovery"),
            "VULNFLOW_DEMO_MODE": "1",
            "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
            "VULNFLOW_JOB_WORKER_ENABLED": "0",
            "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
            "VULNFLOW_WEBHOOK_INTERVAL_SECONDS": "0",
            "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
            "VULNFLOW_BACKUP_INTERVAL_HOURS": "0",
            "VULNFLOW_COOKIE_SECURE": "0",
        }
    )
    log_path = tmp_path / "uvicorn-e2e.log"
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            _wait_until_ready(base_url, process, log_path)
            yield base_url
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log_handle.flush()
            if process.returncode not in {0, -15, 1}:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"VulnFlow shutdown failed (code={process.returncode}).\n{output}")


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        executable = os.getenv("VULNFLOW_E2E_CHROMIUM", "").strip()
        launch_options = {"headless": True}
        if executable:
            launch_options["executable_path"] = executable
        instance = playwright.chromium.launch(**launch_options)
        try:
            yield instance
        finally:
            instance.close()


def _page(browser: Browser, base_url: str, credentials: dict[str, str]) -> tuple[Page, object]:
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    page.goto("/login")
    page.locator("input[name='username']").fill(credentials["username"])
    page.locator("input[name='password']").fill(credentials["password"])
    page.get_by_role("button", name="로그인").click()
    expect(page).to_have_url(re.compile(rf"^{re.escape(base_url)}/(?:$|\?)"))
    return page, context




def _success_notice(page: Page, text: str):
    return page.locator(".notice.success").filter(has_text=text).first


def _advanced_section(page: Page, summary_text: str):
    return page.locator("details.advanced-section").filter(
        has=page.locator("summary", has_text=summary_text)
    ).first

def test_dashboard_to_finding_workflow_update(browser: Browser, live_server: str) -> None:
    page, context = _page(browser, live_server, ADMIN)
    try:
        page.goto("/")
        expect(page.get_by_role("heading", name="전체 조치 항목")).to_be_visible()
        page.locator("#findings a.finding-link[href='/finding/F-0001']").click()
        expect(page).to_have_url(re.compile(r"/finding/F-0001$"))
        expect(
            page.locator("nav.breadcrumb").get_by_text("F-0001", exact=True)
        ).to_be_visible()
        expect(page.get_by_role("heading", level=1)).to_contain_text(
            "EdgeConnect Gateway · CVE-2024-3400"
        )

        workflow = page.locator("form").filter(has=page.locator("select[name='status']")).first
        workflow.locator("select[name='status']").select_option("IN_PROGRESS")
        workflow.locator("input[name='owner']").fill("browser-e2e-owner")
        workflow.locator("textarea[name='notes']").fill("Playwright browser workflow update")
        workflow.get_by_role("button", name="저장하고 반영").click()

        expect(_success_notice(page, "조치 워크플로를 저장하고 재평가했습니다.")).to_be_visible()
        expect(workflow.locator("select[name='status']")).to_have_value("IN_PROGRESS")
        expect(workflow.locator("input[name='owner']")).to_have_value("browser-e2e-owner")
    finally:
        context.close()


def test_csv_import_creates_searchable_finding(browser: Browser, live_server: str) -> None:
    page, context = _page(browser, live_server, ADMIN)
    try:
        page.goto("/upload")
        expect(page.get_by_role("heading", name="취약점 결과를 가져오세요.")).to_be_visible()
        upload_form = page.locator("form[action='/upload/findings/preview']")
        upload_form.locator("input[name='scanner_source']").fill("browser-e2e")
        csv_content = (
            "finding_id,product,cve_id,asset_name,environment,component,component_version,"
            "cvss,epss,epss_percentile,kev,internet_exposed,asset_criticality,"
            "data_sensitivity,patch_available,status,notes\n"
            "E2E-0001,E2E Browser Service,CVE-2099-9999,E2E Browser Asset,production,"
            "e2e-component,1.0,9.1,0.50,0.90,0,1,4,3,1,OPEN,Playwright CSV import\n"
        )
        upload_form.locator("input[type='file']").set_input_files(
            {
                "name": "e2e-findings.csv",
                "mimeType": "text/csv",
                "buffer": csv_content.encode("utf-8"),
            }
        )
        upload_form.get_by_role("button", name="파일 분석하고 미리보기").click()
        expect(page.get_by_role("heading", name="반영 전에 결과를 확인하세요.")).to_be_visible()
        page.get_by_role("button", name="1건 목록에 반영").click()

        expect(page.get_by_text("취약점 결과를 반영했습니다.")).to_be_visible()
        page.locator("#findings input[name='query']").fill("CVE-2099-9999")
        page.locator("#findings form.dashboard-filters").get_by_role(
            "button", name="검색"
        ).click()
        expect(page.locator("#findings").get_by_text("CVE-2099-9999", exact=False)).to_be_visible()
        expect(page.get_by_text("E2E Browser Asset", exact=False)).to_be_visible()
    finally:
        context.close()


def test_operator_risk_acceptance_requires_approver(browser: Browser, live_server: str) -> None:
    operator_page, operator_context = _page(browser, live_server, OPERATOR)
    try:
        operator_page.goto("/finding/F-0004")
        workflow = operator_page.locator("form").filter(
            has=operator_page.locator("select[name='status']")
        ).first
        workflow.locator("select[name='status']").select_option("RISK_ACCEPTED")
        workflow.locator("details.exception-fields summary").click()
        workflow.locator("input[name='exception_expiry']").fill("2099-12-31")
        workflow.locator("textarea[name='risk_acceptance_reason']").fill(
            "Browser E2E validates approval separation"
        )
        workflow.locator("textarea[name='notes']").fill("Temporary acceptance request")
        workflow.get_by_role("button", name="저장하고 반영").click()
        expect(_success_notice(operator_page, "위험수용 승인 요청을 생성했습니다.")).to_be_visible()
    finally:
        operator_context.close()

    admin_page, admin_context = _page(browser, live_server, ADMIN)
    try:
        admin_page.goto("/approvals?status=PENDING")
        request_row = admin_page.locator("tr").filter(has=admin_page.locator("a[href='/finding/F-0004']")).first
        expect(request_row).to_be_visible()
        expect(request_row.get_by_text("PENDING", exact=True)).to_be_visible()
        request_row.locator("textarea[name='decision_note']").fill(
            "Browser E2E approver decision"
        )
        request_row.locator("button[value='APPROVED']").click()
        expect(_success_notice(admin_page, "위험수용 승인 요청을 처리했습니다.")).to_be_visible()

        admin_page.goto("/finding/F-0004")
        workflow = admin_page.locator("form").filter(
            has=admin_page.locator("select[name='status']")
        ).first
        expect(workflow.locator("select[name='status']")).to_have_value("RISK_ACCEPTED")
        approval_history = _advanced_section(admin_page, "예외 승인 이력")
        approval_history.locator("summary").click()
        expect(
            approval_history.locator("strong").filter(
                has_text=re.compile(r"^APPROVED · APR-")
            ).first
        ).to_be_visible()
    finally:
        admin_context.close()
