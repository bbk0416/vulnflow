from __future__ import annotations

"""Exercise VulnFlow behind a real local nginx TLS reverse proxy.

The rehearsal generates a one-day self-signed CA certificate, starts a
pilot-profile Uvicorn process with dependency drift reported but not enforced and the host nginx binary on ephemeral
loopback ports, performs browser-style login over verified HTTPS, and confirms
that the edge proxy overwrites spoofed X-Forwarded-For input.

It validates the host runtime contract; it does not claim that Docker networking,
public DNS, ACME certificate renewal, or an external backup appliance ran.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
ADMIN_USERNAME = "rehearsal-admin"
ADMIN_PASSWORD = "Rehearsal-Only-Password!42"
USER_AGENT = "VulnFlow-Live-TLS-Rehearsal/1.0"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _require(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise RuntimeError(
            f"{label} failed ({result.returncode})\n"
            f"stdout:\n{result.stdout[-4000:]}\n"
            f"stderr:\n{result.stderr[-4000:]}"
        )


def _terminate(process: subprocess.Popen[Any] | None, *, timeout: int = 12) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def _runtime_environment(work: Path, https_port: int) -> dict[str, str]:
    data = work / "data"
    external = work / "external-backups"
    project = data / "projects" / "default"
    for directory in (data, external, project):
        directory.mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("VULNFLOW_")}
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONPATH": str(ROOT),
            "VULNFLOW_DATA_DIR": str(data),
            "VULNFLOW_CONTROL_DB": str(data / "control.db"),
            "VULNFLOW_PROJECTS_DIR": str(data / "projects"),
            "VULNFLOW_DEFAULT_PROJECT_ROOT": str(project),
            "VULNFLOW_DEFAULT_PROJECT_DB": str(project / "vulnflow.db"),
            "VULNFLOW_COORDINATION_DB": str(data / "coordination.db"),
            "VULNFLOW_SECURITY_PROFILE": "pilot",
            "VULNFLOW_RUNTIME_DEPENDENCY_POLICY": "warn",
            "VULNFLOW_PUBLIC_BASE_URL": f"https://localhost:{https_port}",
            "VULNFLOW_DEMO_MODE": "0",
            "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
            "VULNFLOW_COOKIE_SECURE": "1",
            "VULNFLOW_AUTH_SESSION_BINDING": "user-agent",
            "VULNFLOW_AUTH_SESSION_IDLE_MINUTES": "60",
            "VULNFLOW_AUTH_SESSION_MINUTES": "480",
            "VULNFLOW_CURSOR_SIGNING_KEY": "live-rehearsal-cursor-key-0123456789",
            "VULNFLOW_AUDIT_SIGNING_KEY": "live-rehearsal-audit-key-0123456789",
            "VULNFLOW_BACKUP_SIGNING_KEY": "live-rehearsal-backup-key-0123456789",
            "VULNFLOW_AUDIT_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_BACKUP_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_BACKUP_INTERVAL_HOURS": "12",
            "VULNFLOW_EXTERNAL_BACKUP_DIR": str(external),
            "VULNFLOW_EVIDENCE_SCANNER_MODE": "builtin",
            "VULNFLOW_EVIDENCE_REQUIRE_CLEAN": "1",
            "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
            "VULNFLOW_JOB_WORKER_ENABLED": "0",
            "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
            # This host rehearsal has one loopback proxy.  Production Compose
            # uses * only on an internal network whose edge overwrites XFF.
            "FORWARDED_ALLOW_IPS": "127.0.0.1",
        }
    )
    return env


def _generate_certificate(work: Path, openssl: str) -> tuple[Path, Path]:
    cert_dir = work / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    certificate = cert_dir / "fullchain.pem"
    private_key = cert_dir / "privkey.pem"
    result = _run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        timeout=60,
    )
    _require(result, "self-signed TLS certificate generation")
    private_key.chmod(0o600)
    return certificate, private_key


def _render_nginx_configuration(
    work: Path,
    *,
    app_port: int,
    http_port: int,
    https_port: int,
    certificate: Path,
    private_key: Path,
) -> Path:
    deployed = (ROOT / "deploy" / "nginx" / "vulnflow.conf").read_text(encoding="utf-8")
    replacements = {
        "listen 80;": f"listen 127.0.0.1:{http_port};",
        "return 301 https://$host$request_uri;": (
            f"return 301 https://localhost:{https_port}$request_uri;"
        ),
        "listen 443 ssl;": f"listen 127.0.0.1:{https_port} ssl;",
        "/etc/nginx/certs/fullchain.pem": str(certificate),
        "/etc/nginx/certs/privkey.pem": str(private_key),
        "proxy_pass http://vulnflow:8000;": f"proxy_pass http://127.0.0.1:{app_port};",
    }
    for old, new in replacements.items():
        if old not in deployed:
            raise RuntimeError(f"nginx deployment template contract changed: missing {old!r}")
        deployed = deployed.replace(old, new)
    config = work / "nginx.conf"
    config.write_text(
        f"pid {work / 'nginx.pid'};\n"
        f"error_log {work / 'nginx-error.log'} info;\n"
        "events { worker_connections 128; }\n"
        "http {\n"
        f"access_log {work / 'nginx-access.log'};\n"
        f"{deployed}\n"
        "}\n",
        encoding="utf-8",
    )
    return config


def _wait_direct_ready(
    app_port: int, app: subprocess.Popen[Any], *, timeout: float = 35
) -> None:
    session = requests.Session()
    session.trust_env = False
    deadline = time.monotonic() + timeout
    last_error = ""
    try:
        while time.monotonic() < deadline:
            if app.poll() is not None:
                raise RuntimeError(f"uvicorn exited before direct readiness with code {app.returncode}")
            try:
                response = session.get(
                    f"http://127.0.0.1:{app_port}/health/ready", timeout=1
                )
                if response.status_code == 200:
                    return
                last_error = f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                last_error = str(exc)
            time.sleep(0.15)
    finally:
        session.close()
    raise RuntimeError(f"direct Uvicorn readiness timed out: {last_error}")


def _wait_ready(
    session: requests.Session,
    base_url: str,
    certificate: Path,
    app: subprocess.Popen[Any],
    proxy: subprocess.Popen[Any],
    *,
    timeout: float = 35,
) -> requests.Response:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        for label, process in (("uvicorn", app), ("nginx", proxy)):
            if process.poll() is not None:
                raise RuntimeError(f"{label} exited before readiness with code {process.returncode}")
        try:
            response = session.get(
                base_url + "/health/ready", verify=str(certificate), timeout=1
            )
            if response.status_code == 200:
                return response
            last_error = f"HTTP {response.status_code}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(0.15)
    raise RuntimeError(f"HTTPS readiness timed out: {last_error}")


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise RuntimeError("login page did not contain a CSRF token")
    return match.group(1)


def _tls_protocol(
    openssl: str, port: int, certificate: Path, option: str
) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            openssl,
            "s_client",
            "-connect",
            f"127.0.0.1:{port}",
            "-servername",
            "localhost",
            "-CAfile",
            str(certificate),
            "-verify_return_error",
            option,
        ],
        input_text="",
        timeout=15,
    )


def _latest_failed_client(control_db: Path) -> str:
    with sqlite3.connect(control_db) as connection:
        row = connection.execute(
            "SELECT client_key FROM auth_login_attempts WHERE succeeded=0 "
            "ORDER BY attempt_id DESC LIMIT 1"
        ).fetchone()
    return str(row[0]) if row else ""


def run_live_rehearsal(work: Path) -> dict[str, Any]:
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    if not nginx or not openssl:
        missing = [name for name, value in (("nginx", nginx), ("openssl", openssl)) if not value]
        raise FileNotFoundError("required live rehearsal commands are missing: " + ", ".join(missing))

    work.mkdir(parents=True, exist_ok=True)
    app_port, http_port, https_port = _free_port(), _free_port(), _free_port()
    certificate, private_key = _generate_certificate(work, openssl)
    environment = _runtime_environment(work, https_port)
    control_db = Path(environment["VULNFLOW_CONTROL_DB"])

    create = _run(
        [
            sys.executable,
            "-m",
            "scripts.manage_users",
            "--db",
            str(control_db),
            "create",
            "--username",
            ADMIN_USERNAME,
            "--role",
            "admin",
            "--password-stdin",
        ],
        env=environment,
        input_text=ADMIN_PASSWORD + "\n",
        timeout=60,
    )
    _require(create, "rehearsal administrator creation")

    nginx_config = _render_nginx_configuration(
        work,
        app_port=app_port,
        http_port=http_port,
        https_port=https_port,
        certificate=certificate,
        private_key=private_key,
    )
    syntax = _run([nginx, "-t", "-c", str(nginx_config), "-p", str(work)])
    _require(syntax, "nginx configuration test")

    app_log_path = work / "uvicorn.log"
    nginx_log_path = work / "nginx-stdout.log"
    app: subprocess.Popen[Any] | None = None
    proxy: subprocess.Popen[Any] | None = None
    checks: dict[str, bool] = {}
    details: dict[str, Any] = {
        "ports": {"app": app_port, "http": http_port, "https": https_port},
        "nginx_configuration_test": (syntax.stdout + syntax.stderr).strip(),
    }
    session = requests.Session()
    session.trust_env = False
    try:
        with app_log_path.open("w", encoding="utf-8") as app_log:
            app = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(app_port),
                    "--proxy-headers",
                    "--forwarded-allow-ips",
                    "127.0.0.1",
                ],
                cwd=ROOT,
                env=environment,
                stdout=app_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=(os.name == "posix"),
            )
        _wait_direct_ready(app_port, app)
        with nginx_log_path.open("w", encoding="utf-8") as nginx_log:
            proxy = subprocess.Popen(
                [
                    nginx,
                    "-c",
                    str(nginx_config),
                    "-p",
                    str(work),
                    "-g",
                    "daemon off; master_process off;",
                ],
                stdout=nginx_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=(os.name == "posix"),
            )

        base_url = f"https://localhost:{https_port}"
        ready = _wait_ready(session, base_url, certificate, app, proxy)
        checks["verified_https_readiness"] = ready.status_code == 200

        redirect = session.get(
            f"http://localhost:{http_port}/login", allow_redirects=False, timeout=3
        )
        checks["http_redirects_to_https"] = (
            redirect.status_code in {301, 308}
            and redirect.headers.get("location") == f"{base_url}/login"
        )

        tls12 = _tls_protocol(openssl, https_port, certificate, "-tls1_2")
        tls13 = _tls_protocol(openssl, https_port, certificate, "-tls1_3")
        tls11 = _tls_protocol(openssl, https_port, certificate, "-tls1_1")
        checks["tls12_accepted"] = tls12.returncode == 0 and "Verify return code: 0" in tls12.stdout
        checks["tls13_accepted"] = tls13.returncode == 0 and "Verify return code: 0" in tls13.stdout
        checks["tls11_rejected"] = tls11.returncode != 0 or "Cipher is (NONE)" in tls11.stdout

        login = session.get(
            base_url + "/login",
            headers={"User-Agent": USER_AGENT, "X-Forwarded-For": "203.0.113.99"},
            verify=str(certificate),
            timeout=5,
        )
        csrf_cookie = login.headers.get("set-cookie", "")
        checks["login_page_over_https"] = login.status_code == 200
        checks["csrf_cookie_secure"] = all(
            marker in csrf_cookie for marker in ("HttpOnly", "Secure", "SameSite=strict")
        )

        authenticated = session.post(
            base_url + "/login",
            headers={"User-Agent": USER_AGENT, "X-Forwarded-For": "203.0.113.99"},
            data={
                "csrf_token": _csrf(login.text),
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
                "next": "/",
            },
            allow_redirects=False,
            verify=str(certificate),
            timeout=8,
        )
        session_cookie = authenticated.headers.get("set-cookie", "")
        checks["database_login_succeeds"] = (
            authenticated.status_code == 303 and authenticated.headers.get("location") == "/"
        )
        checks["session_cookie_secure"] = all(
            marker in session_cookie for marker in ("HttpOnly", "Secure", "SameSite=strict")
        )
        home = session.get(
            base_url + "/",
            headers={"User-Agent": USER_AGENT},
            verify=str(certificate),
            timeout=8,
        )
        checks["authenticated_page_succeeds"] = home.status_code == 200
        checks["hsts_enabled"] = "max-age=" in home.headers.get("strict-transport-security", "")
        checks["frame_protection_enabled"] = home.headers.get("x-frame-options") == "DENY"
        checks["nginx_version_hidden"] = "/" not in home.headers.get("server", "")

        attacker = requests.Session()
        attacker.trust_env = False
        bad_page = attacker.get(
            base_url + "/login",
            headers={"User-Agent": "Spoof-Check/1", "X-Forwarded-For": "198.51.100.7"},
            verify=str(certificate),
            timeout=5,
        )
        bad_login = attacker.post(
            base_url + "/login",
            headers={"User-Agent": "Spoof-Check/1", "X-Forwarded-For": "198.51.100.7"},
            data={
                "csrf_token": _csrf(bad_page.text),
                "username": ADMIN_USERNAME,
                "password": "incorrect-password",
                "next": "/",
            },
            allow_redirects=False,
            verify=str(certificate),
            timeout=8,
        )
        observed_client = _latest_failed_client(control_db)
        checks["spoofed_forwarded_for_overwritten"] = (
            bad_login.status_code == 401
            and observed_client == _fingerprint("127.0.0.1")
            and observed_client != _fingerprint("198.51.100.7")
        )
        details["observed_failed_login_client_fingerprint"] = observed_client
    finally:
        _terminate(proxy)
        _terminate(app)
        session.close()

    details["uvicorn_log_tail"] = (
        app_log_path.read_text(encoding="utf-8", errors="replace")[-2500:]
        if app_log_path.exists()
        else ""
    )
    details["nginx_error_log_tail"] = (
        (work / "nginx-error.log").read_text(encoding="utf-8", errors="replace")[-2500:]
        if (work / "nginx-error.log").exists()
        else ""
    )
    return {
        "format": "vulnflow-live-tls-proxy-rehearsal/1",
        "passed": all(checks.values()),
        "checks": checks,
        "details": details,
        "limitations": [
            "The host nginx and Uvicorn processes were exercised under the pilot profile so local dependency drift cannot mask the TLS transport checks; production dependency enforcement is verified separately.",
            "Docker networking and the container image were not exercised.",
            "The certificate is a one-day self-signed rehearsal CA, not a public ACME or enterprise PKI certificate.",
            "Public DNS, certificate renewal, external backup media, SMTP, Jira, and customer scanner files were not exercised.",
        ],
    }



def _text_report(report: dict[str, Any]) -> str:
    lines = [
        "VulnFlow live TLS proxy rehearsal",
        "",
        f"status: {'PASS' if report['passed'] else 'FAIL'}",
        f"checks: {sum(1 for value in report['checks'].values() if value)}/{len(report['checks'])}",
        "",
        "checks:",
    ]
    lines.extend(
        f"- [{'PASS' if passed else 'FAIL'}] {name}"
        for name, passed in sorted(report["checks"].items())
    )
    lines.extend(["", "limitations:"])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--text-output", type=Path)
    args = parser.parse_args()
    try:
        if args.work_dir:
            report = run_live_rehearsal(args.work_dir)
        else:
            with tempfile.TemporaryDirectory(prefix="vulnflow_live_tls_") as temporary:
                report = run_live_rehearsal(Path(temporary))
    except (FileNotFoundError, RuntimeError, requests.RequestException) as exc:
        print(f"live TLS proxy rehearsal failed: {exc}", file=sys.stderr)
        return 2
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(payload)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload + "\n", encoding="utf-8")
    if args.text_output:
        args.text_output.parent.mkdir(parents=True, exist_ok=True)
        args.text_output.write_text(_text_report(report), encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
