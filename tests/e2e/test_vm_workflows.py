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
def test_full_operator_remediation_verification_closes_finding(
    browser: Browser, live_server: str
) -> None:
    operator_page, operator_context = _page(browser, live_server, OPERATOR)
    admin_context = None

    def import_snapshot(page: Page, csv_content: str, *, expected_count: int) -> None:
        page.goto("/upload")
        upload_form = page.locator("form[action='/upload/findings/preview']")
        upload_form.locator("input[name='scanner_source']").fill("browser-e2e-lifecycle")
        upload_form.locator("select[name='import_mode']").select_option("snapshot")
        upload_form.locator("input[type='file']").set_input_files(
            {
                "name": "browser-e2e-lifecycle.csv",
                "mimeType": "text/csv",
                "buffer": csv_content.encode("utf-8"),
            }
        )
        upload_form.get_by_role("button", name="파일 분석하고 미리보기").click()
        expect(page.get_by_role("heading", name="반영 전에 결과를 확인하세요.")).to_be_visible()
        page.get_by_role("button", name=f"{expected_count}건 목록에 반영").click()
        expect(page.get_by_text("취약점 결과를 반영했습니다.")).to_be_visible()

    try:
        initial_snapshot = (
            "finding_id,product,cve_id,asset_name,cvss,status,notes\n"
            "E2E-FULL-1,Browser Full Journey,CVE-2099-8888,E2E Lifecycle Target,9.4,OPEN,"
            "full browser lifecycle\n"
            "E2E-FULL-KEEP,Browser Sentinel,CVE-2099-8887,E2E Lifecycle Sentinel,3.1,OPEN,"
            "snapshot sentinel\n"
        )
        absent_snapshot = (
            "finding_id,product,cve_id,asset_name,cvss,status,notes\n"
            "E2E-FULL-KEEP,Browser Sentinel,CVE-2099-8887,E2E Lifecycle Sentinel,3.1,OPEN,"
            "snapshot sentinel\n"
        )

        # Operator: import -> triage -> assign -> remediate.
        import_snapshot(operator_page, initial_snapshot, expected_count=2)
        operator_page.goto("/?query=CVE-2099-8888")
        result_row = operator_page.locator("#findings tr").filter(
            has_text="CVE-2099-8888"
        ).first
        expect(result_row).to_be_visible()
        finding_link = result_row.locator("a.finding-link").first
        href = finding_link.get_attribute("href")
        assert href and href.startswith("/finding/")
        finding_id = href.rsplit("/", 1)[-1]
        finding_link.click()
        expect(operator_page).to_have_url(
            re.compile(rf"/finding/{re.escape(finding_id)}$")
        )

        workflow = operator_page.locator("form").filter(
            has=operator_page.locator("select[name='status']")
        ).first
        workflow.locator("select[name='status']").select_option("IN_PROGRESS")
        workflow.locator("input[name='owner']").fill("browser-remediation-owner")
        workflow.locator("textarea[name='notes']").fill(
            "Browser E2E remediation started"
        )
        workflow.get_by_role("button", name="저장하고 반영").click()
        expect(workflow.locator("select[name='status']")).to_have_value(
            "IN_PROGRESS"
        )
        expect(workflow.locator("input[name='owner']")).to_have_value(
            "browser-remediation-owner"
        )

        workflow.locator("select[name='status']").select_option("MITIGATED")
        workflow.locator("textarea[name='notes']").fill(
            "Browser E2E remediation completed"
        )
        workflow.get_by_role("button", name="저장하고 반영").click()
        expect(workflow.locator("select[name='status']")).to_have_value(
            "MITIGATED"
        )

        # Operator: two complete snapshots prove scanner absence.
        import_snapshot(operator_page, absent_snapshot, expected_count=1)
        import_snapshot(operator_page, absent_snapshot, expected_count=1)

        # Operator: request remediation verification.
        operator_page.goto(f"/finding/{finding_id}")
        verification_form = operator_page.locator(
            f"form[action='/finding/{finding_id}/verification-requests']"
        )
        expect(verification_form).to_be_visible()
        verification_form.locator("select[name='method']").select_option(
            "SCAN_ABSENCE"
        )
        verification_form.locator("textarea[name='evidence_note']").fill(
            "Two browser-driven clean scanner snapshots"
        )
        verification_form.get_by_role("button", name="조치 검증 요청").click()

        # Approval separation: leave the operator session before review.
        operator_context.close()
        operator_context = None

        # Admin/approver: review the pending request in the actual UI queue.
        admin_page, admin_context = _page(browser, live_server, ADMIN)
        admin_page.goto("/verifications?status=PENDING")
        finding_anchor = admin_page.locator(
            f"a[href='/finding/{finding_id}']"
        ).first
        expect(finding_anchor).to_be_visible()
        request_scope = finding_anchor.locator(
            "xpath=ancestor::*[.//form[contains(@action, '/verifications/')]][1]"
        )
        expect(request_scope).to_be_visible()
        decision_form = request_scope.locator(
            "form[action^='/verifications/'][action$='/decision']"
        ).first
        expect(decision_form).to_be_visible()

        decision_form.locator("select[name='decision']").select_option("APPROVE")
        decision_form.locator("input[name='decision_note']").fill(
            "Browser E2E confirmed scanner absence"
        )
        decision_form.get_by_role("button", name="판정 저장").click()

        # Controlled close must be visible in the browser after approval.
        admin_page.goto(f"/finding/{finding_id}")
        closed_workflow = admin_page.locator("form").filter(
            has=admin_page.locator("select[name='status']")
        ).first
        expect(closed_workflow.locator("select[name='status']")).to_have_value(
            "CLOSED"
        )
    finally:
        if operator_context is not None:
            operator_context.close()
        if admin_context is not None:
            admin_context.close()
