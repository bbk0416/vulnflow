from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen

import requests
from playwright.sync_api import Browser, Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ADMIN = {"username": "admin-capture", "password": "Admin-Capture-Password-42!"}
OPERATOR = {"username": "operator-capture", "password": "Operator-Capture-Password-42!"}
SCREENSHOTS = (
    "dashboard.png",
    "finding-detail.png",
    "asset-inventory.png",
    "data-import.png",
    "risk-approvals.png",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"VulnFlow exited before readiness.\n{output}")
        try:
            with urlopen(f"{base_url}/health/live", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, URLError) as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(f"VulnFlow did not become ready: {last_error}")


def _page(browser: Browser, base_url: str, credentials: dict[str, str]) -> tuple[Page, object]:
    # Screenshots are rendered from server HTML fetched with the dedicated
    # capture bearer token below.  Keeping the browser page originless avoids
    # managed-browser policies that block loopback navigation while preserving
    # the exact server-rendered HTML/CSS used by the product.
    context = browser.new_context(
        viewport={"width": 1440, "height": 1000},
        device_scale_factor=1,
        locale="ko-KR",
        reduced_motion="reduce",
    )
    page = context.new_page()
    return page, context


def _capture(page: Page, relative_url: str, output: Path) -> None:
    page.goto(relative_url, wait_until="networkidle")
    page.screenshot(path=output, full_page=True, animations="disabled")


def _create_pending_approval(database: Path) -> None:
    from app.repositories.finding_approvals import create_risk_approval_request

    create_risk_approval_request(
        database,
        "F-0004",
        requested_by=OPERATOR["username"],
        reason="합성 데이터 기반 공개 화면 캡처용 위험수용 요청",
        exception_expiry="2099-12-31",
        notes="Public screenshot fixture",
    )


def _render_server_html(page: Page, base_url: str, route: str, output: Path) -> None:
    response = requests.get(
        f"{base_url}{route}",
        headers={"Authorization": "Bearer capture-admin-token-123456789"},
        timeout=10,
    )
    response.raise_for_status()
    stylesheet = (ROOT / "app/static/style.css").read_text(encoding="utf-8")
    html = response.text.replace(
        '<link rel="stylesheet" href="/static/style.css">',
        f"<style>{stylesheet}</style>",
    )
    page.set_content(html, wait_until="load")
    page.screenshot(path=output, full_page=True, animations="disabled")


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture five repeatable public VulnFlow screenshots.")
    parser.add_argument("--output", default="assets/screenshots")
    args = parser.parse_args()
    output_dir = (ROOT / args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="vulnflow-public-capture-") as temp:
        data_dir = Path(temp) / "data"
        control_db = data_dir / "control.db"
        default_project_root = data_dir / "projects" / "default"
        database = default_project_root / "vulnflow.db"
        from app.core.database_schema import init_db
        from app.services.accounts import create_user
        init_db(control_db)
        create_user(control_db, username=ADMIN["username"], password=ADMIN["password"], role="admin", actor="capture-bootstrap")
        create_user(control_db, username=OPERATOR["username"], password=OPERATOR["password"], role="operator", actor="capture-bootstrap")
        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.update(
            {
                "PYTHONUNBUFFERED": "1",
                "VULNFLOW_BASE_DIR": str(ROOT),
                "VULNFLOW_DATA_DIR": str(data_dir),
                "VULNFLOW_CONTROL_DB": str(control_db),
                "VULNFLOW_PROJECTS_DIR": str(data_dir / "projects"),
                "VULNFLOW_DEFAULT_PROJECT_ROOT": str(default_project_root),
                "VULNFLOW_DEFAULT_PROJECT_DB": str(database),
                "VULNFLOW_DB": str(data_dir / "legacy-vulnflow.db"),
                "VULNFLOW_EVIDENCE_DIR": str(default_project_root / "evidence"),
                "VULNFLOW_EXPORT_DIR": str(default_project_root / "exports"),
                "VULNFLOW_IMPORT_PREVIEW_DIR": str(default_project_root / "import-previews"),
                "VULNFLOW_RECOVERY_DIR": str(default_project_root / "backups" / "recovery"),
                "VULNFLOW_DEMO_MODE": "1",
                "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
                "VULNFLOW_API_TOKENS_JSON": json.dumps({"capture-admin": {"token": "capture-admin-token-123456789", "role": "admin", "projects": "*"}}),
                "VULNFLOW_JOB_WORKER_ENABLED": "0",
                "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
                "VULNFLOW_WEBHOOK_INTERVAL_SECONDS": "0",
                "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
                "VULNFLOW_BACKUP_INTERVAL_HOURS": "0",
                "VULNFLOW_COOKIE_SECURE": "0",
            }
        )
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
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            _wait_until_ready(base_url, process)
            with sync_playwright() as playwright:
                executable = os.getenv("VULNFLOW_E2E_CHROMIUM", "").strip()
                launch_options: dict[str, object] = {"headless": True}
                if executable:
                    launch_options["executable_path"] = executable
                browser = playwright.chromium.launch(**launch_options)
                try:
                    _create_pending_approval(database)
                    page, context = _page(browser, base_url, ADMIN)
                    try:
                        routes = (
                            ("/", "dashboard.png"),
                            ("/finding/F-0001", "finding-detail.png"),
                            ("/assets", "asset-inventory.png"),
                            ("/upload", "data-import.png"),
                            ("/approvals?status=PENDING", "risk-approvals.png"),
                        )
                        for route, filename in routes:
                            _render_server_html(page, base_url, route, output_dir / filename)
                            print(f"captured: {filename}")
                    finally:
                        context.close()
                finally:
                    browser.close()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    missing = [name for name in SCREENSHOTS if not (output_dir / name).is_file()]
    if missing:
        raise SystemExit("missing screenshots: " + ", ".join(missing))
    print(f"public screenshot capture: PASS ({len(SCREENSHOTS)}/{len(SCREENSHOTS)})")


if __name__ == "__main__":
    main()
