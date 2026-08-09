from __future__ import annotations

"""Build and exercise the production Docker Compose TLS topology when Docker exists."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.local_tls_certificate import generate_self_signed_certificate


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _require(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise RuntimeError(
            f"{label} failed\nstdout:\n{result.stdout[-4000:]}\nstderr:\n{result.stderr[-4000:]}"
        )


def _certificate(directory: Path) -> tuple[Path, Path]:
    return generate_self_signed_certificate(
        directory,
        common_name="localhost",
        dns_names=("localhost",),
        ip_addresses=("127.0.0.1",),
        certificate_name="fullchain.pem",
        private_key_name="privkey.pem",
    )


def build_rehearsal_compose(
    root: Path,
    *,
    certificate_directory: Path,
    http_port: int,
    https_port: int,
    image: str,
) -> dict[str, Any]:
    compose = yaml.safe_load(
        (root / "docker-compose.production.yml").read_text(encoding="utf-8")
    ) or {}
    services = compose.setdefault("services", {})
    app = services.setdefault("vulnflow", {})
    proxy = services.setdefault("proxy", {})
    app["build"] = {"context": str(root.resolve())}
    app["image"] = image
    app.pop("ports", None)
    proxy["ports"] = [
        f"127.0.0.1:{http_port}:80",
        f"127.0.0.1:{https_port}:443",
    ]
    proxy["volumes"] = [
        {
            "type": "bind",
            "source": str((root / "deploy/nginx/vulnflow.conf").resolve()),
            "target": "/etc/nginx/conf.d/default.conf",
            "read_only": True,
        },
        {
            "type": "bind",
            "source": str(certificate_directory.resolve()),
            "target": "/etc/nginx/certs",
            "read_only": True,
        },
    ]
    return compose


def rehearsal_environment(*, https_port: int) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "VULNFLOW_PUBLIC_BASE_URL": f"https://localhost:{https_port}",
        "VULNFLOW_CURSOR_SIGNING_KEY": "compose-rehearsal-cursor-key-0123456789abcdef",
        "VULNFLOW_AUDIT_SIGNING_KEY": "compose-rehearsal-audit-key-0123456789abcdef",
        "VULNFLOW_BACKUP_SIGNING_KEY": "compose-rehearsal-backup-key-0123456789abcdef",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({
            "compose-admin": {
                "token": "compose-rehearsal-admin-token-0123456789",
                "role": "admin",
                "projects": ["default"],
            }
        }),
        "VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS": "0",
        "VULNFLOW_OUTBOUND_HOST_ALLOWLIST": "*.atlassian.net",
        "VULNFLOW_SMTP_ALLOW_PRIVATE_NETWORKS": "0",
        "VULNFLOW_SMTP_HOST_ALLOWLIST": "smtp.example.com",
        "VULNFLOW_SMTP_ALLOW_PLAIN": "0",
        "VULNFLOW_IMAGE": "unused-by-generated-compose",
    })
    return env


def _wait_https(url: str, *, cafile: Path, timeout_seconds: int = 90) -> requests.Response:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, verify=str(cafile), timeout=3)
            if response.status_code == 200:
                return response
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"production Compose did not become ready: {last_error}")


def run_docker_rehearsal(root: Path = ROOT) -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        raise FileNotFoundError("docker command not found")
    _require(_run([docker, "compose", "version"], timeout=30), "docker compose availability")

    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    http_port, https_port = _free_port(), _free_port()
    project = f"vulnflow-prod-{os.getpid()}-{int(time.time())}"
    image = f"vulnflow:{version}-production-compose-rehearsal"
    checks: dict[str, bool] = {}

    with tempfile.TemporaryDirectory(prefix="vulnflow-production-compose-") as raw:
        work = Path(raw)
        certificate_directory = work / "certs"
        certificate_directory.mkdir()
        cert, _ = _certificate(certificate_directory)
        compose = build_rehearsal_compose(
            root,
            certificate_directory=work / "certs",
            http_port=http_port,
            https_port=https_port,
            image=image,
        )
        compose_file = work / "compose.yml"
        compose_file.write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
        env = rehearsal_environment(https_port=https_port)
        command = [docker, "compose", "-p", project, "-f", str(compose_file)]
        try:
            _require(_run([*command, "config"], env=env, timeout=60), "docker compose config")
            _require(
                _run([*command, "up", "--build", "--detach"], env=env, timeout=900),
                "production docker compose up",
            )
            ready_url = f"https://localhost:{https_port}/health/ready"
            try:
                ready = _wait_https(ready_url, cafile=cert)
            except RuntimeError as exc:
                status = _run([*command, "ps", "--all"], env=env, timeout=30)
                logs = _run([*command, "logs", "--no-color", "--tail", "200"], env=env, timeout=60)
                diagnostic = "\n".join(
                    part for part in (
                        f"compose status:\n{status.stdout[-4000:]}\n{status.stderr[-2000:]}",
                        f"compose logs:\n{logs.stdout[-12000:]}\n{logs.stderr[-4000:]}",
                    ) if part.strip()
                )
                raise RuntimeError(f"{exc}\n{diagnostic}") from exc
            checks["https_readiness"] = ready.status_code == 200

            redirect = requests.get(
                f"http://127.0.0.1:{http_port}/health/ready",
                allow_redirects=False,
                timeout=3,
            )
            checks["http_redirects_to_https"] = (
                redirect.status_code in {301, 302, 307, 308}
                and str(redirect.headers.get("Location") or "").startswith("https://")
            )
            token = "compose-rehearsal-admin-token-0123456789"
            headers = {"Authorization": f"Bearer {token}"}
            root_response = requests.get(
                f"https://localhost:{https_port}/", headers=headers,
                verify=str(cert), timeout=5,
            )
            checks["authenticated_proxy_request"] = root_response.status_code == 200

            import_response = requests.post(
                f"https://localhost:{https_port}/api/v1/imports/csv?scanner_source=compose-rehearsal",
                headers=headers,
                files={
                    "file": (
                        "compose.csv",
                        b"finding_id,product,cve_id,cvss\nCOMPOSE-1,Compose,CVE-2026-99001,8.8\n",
                        "text/csv",
                    )
                },
                verify=str(cert), timeout=10,
            )
            checks["api_import"] = import_response.status_code in {200, 201, 202}
            _require(_run([*command, "restart", "vulnflow"], env=env, timeout=120), "app restart")
            _wait_https(ready_url, cafile=cert)
            detail = requests.get(
                f"https://localhost:{https_port}/api/v1/findings/COMPOSE-1",
                headers=headers, verify=str(cert), timeout=5,
            )
            checks["named_volume_persistence"] = detail.status_code == 200

            uid = _run([*command, "exec", "-T", "vulnflow", "id", "-u"], env=env, timeout=30)
            checks["nonroot_uid"] = uid.returncode == 0 and uid.stdout.strip() == "10001"
            published = _run([*command, "port", "vulnflow", "8000"], env=env, timeout=30)
            checks["app_port_not_published"] = published.returncode != 0 or not published.stdout.strip()
            network = _run(
                [docker, "network", "inspect", f"{project}_backend", "--format", "{{.Internal}}"],
                env=env, timeout=30,
            )
            checks["backend_network_internal"] = network.returncode == 0 and network.stdout.strip().lower() == "true"
        finally:
            _run([*command, "down", "--volumes", "--remove-orphans"], env=env, timeout=180)
            _run([docker, "image", "rm", "--force", image], env=env, timeout=120)

    return {
        "format": "vulnflow-production-compose-rehearsal/1",
        "passed": bool(checks) and all(checks.values()),
        "version": version,
        "checks": checks,
        "limitations": [
            "The rehearsal uses a temporary self-signed localhost certificate.",
            "It does not validate public DNS, certificate renewal, customer storage drivers, or external backup media.",
        ],
    }


def _docker_engine_probe(docker: str) -> tuple[bool, str]:
    result = _run(
        [docker, "info", "--format", "{{json .ServerVersion}}"],
        timeout=30,
    )
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout or "docker engine is unavailable").strip()
    return False, detail[-4000:]


def run_rehearsal(root: Path = ROOT, *, require_docker: bool = False) -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        if require_docker:
            raise FileNotFoundError("docker command not found")
        return {
            "format": "vulnflow-production-compose-rehearsal/1",
            "passed": None,
            "available": False,
            "reason": "docker command not found",
        }
    engine_available, engine_reason = _docker_engine_probe(docker)
    if not engine_available:
        if require_docker:
            raise RuntimeError(f"docker engine unavailable: {engine_reason}")
        return {
            "format": "vulnflow-production-compose-rehearsal/1",
            "status": "unavailable",
            "passed": None,
            "available": False,
            "reason": f"docker engine unavailable: {engine_reason}",
        }
    return {**run_docker_rehearsal(root), "available": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-docker", action="store_true")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    exit_code = 0
    try:
        report = run_rehearsal(require_docker=args.require_docker)
    except (FileNotFoundError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        docker_available = shutil.which("docker") is not None
        report = {
            "format": "vulnflow-production-compose-rehearsal/1",
            "status": "failed" if docker_available else "unavailable",
            "passed": False,
            "available": docker_available,
            "reason": str(exc),
            "error_type": exc.__class__.__name__,
        }
        exit_code = 1
        print(f"production Compose rehearsal failed: {exc}", file=sys.stderr)
    else:
        if report.get("passed") is True:
            report["status"] = "passed"
        elif report.get("available") is False:
            report["status"] = "unavailable"
            report["passed"] = False
        else:
            report["status"] = "failed"
            report["passed"] = False
            exit_code = 1
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(payload)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
