from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
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
import yaml

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_UID = 10001
DEFAULT_GID = 10001
REPORT_JSON = ROOT / "reports" / "container_deployment_rehearsal_verification.json"
REPORT_TEXT = ROOT / "reports" / "container_deployment_rehearsal_verification.txt"

from app.core.database_schema import CURRENT_SCHEMA_VERSION

EXPECTED_SCHEMA_VERSION = CURRENT_SCHEMA_VERSION


@dataclass(frozen=True)
class RuntimeIdentity:
    command_prefix: tuple[str, ...]
    expected_uid: int | None
    expected_gid: int | None
    mode: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def validate_container_contract(root: Path) -> dict[str, bool]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8")) or {}
    service = ((compose.get("services") or {}).get("vulnflow") or {})
    environment = service.get("environment") or {}
    ports = [str(item) for item in service.get("ports") or []]
    volumes = [str(item) for item in service.get("volumes") or []]

    command_line = " ".join(line.strip() for line in dockerfile.splitlines())
    return {
        "docker_python_312": dockerfile.lstrip().startswith("FROM python:3.12-slim"),
        "docker_locked_dependencies": "pip install --no-cache-dir -r requirements.lock" in command_line,
        "docker_nonroot_user": "USER vulnflow" in dockerfile and "--uid 10001 vulnflow" in command_line,
        "docker_fallback_disabled": "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=0" in dockerfile,
        "docker_persistent_volume": 'VOLUME ["/app/data"]' in dockerfile,
        "docker_ready_healthcheck": "/health/ready" in dockerfile and "127.0.0.1:8000" in dockerfile,
        "docker_uvicorn_contract": "app.main:app" in dockerfile and '"--host", "0.0.0.0"' in dockerfile,
        "compose_versioned_image": f"vulnflow:{version}" in str(service.get("image") or ""),
        "compose_loopback_publish": "127.0.0.1:8000:8000" in ports,
        "compose_named_data_volume": any(item.endswith(":/app/data") for item in volumes),
        "compose_fallback_disabled": str(environment.get("VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK") or "").endswith(":-0}"),
        "compose_coordination_in_volume": str(environment.get("VULNFLOW_COORDINATION_DB") or "").startswith("/app/data/"),
        "compose_evidence_in_volume": str(environment.get("VULNFLOW_EVIDENCE_DIR") or "").startswith("/app/data/"),
        "compose_restart_policy": service.get("restart") == "unless-stopped",
    }


def _runtime_identity() -> RuntimeIdentity:
    if os.name != "posix":
        return RuntimeIdentity((), None, None, "current-user-non-posix")
    effective_uid = os.geteuid()
    effective_gid = os.getegid()
    if effective_uid != 0:
        return RuntimeIdentity((), effective_uid, effective_gid, "current-nonroot-user")
    return RuntimeIdentity((), DEFAULT_UID, DEFAULT_GID, "preexec-uid-10001")



def _preexec_for_identity(identity: RuntimeIdentity):
    if os.name != "posix" or os.geteuid() != 0 or identity.expected_uid is None:
        return None

    def drop_privileges() -> None:
        os.setgroups([])
        os.setgid(identity.expected_gid or identity.expected_uid)
        os.setuid(identity.expected_uid)

    return drop_privileges

def _copy_readonly_source(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv",
        "*.pyc", "*.pyo", "*.db", "*.sqlite3", "*-wal", "*-shm",
    )
    shutil.copytree(source, destination, ignore=ignored)
    for path in sorted(destination.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o555)
        else:
            executable = bool(path.stat().st_mode & 0o111)
            path.chmod(0o555 if executable else 0o444)
    destination.chmod(0o555)


def _prepare_volume(volume: Path, identity: RuntimeIdentity) -> None:
    for relative in ("", "evidence", "recovery", "exports", "home", "tmp", "cache"):
        path = volume / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    if os.name == "posix" and identity.expected_uid is not None and os.geteuid() == 0:
        for path in [volume, *volume.rglob("*")]:
            if not path.is_symlink():
                os.chown(path, identity.expected_uid, identity.expected_gid or identity.expected_uid)


def _deployment_environment(volume: Path, cycle: int) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("VULNFLOW_")}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "HOME": str(volume / "home"),
        "TMPDIR": str(volume / "tmp"),
        "XDG_CACHE_HOME": str(volume / "cache"),
        "VULNFLOW_DATA_DIR": str(volume),
        "VULNFLOW_CONTROL_DB": str(volume / "control.db"),
        "VULNFLOW_PROJECTS_DIR": str(volume / "projects"),
        "VULNFLOW_DEFAULT_PROJECT_ROOT": str(volume / "projects" / "default"),
        "VULNFLOW_DEFAULT_PROJECT_DB": str(volume / "projects" / "default" / "vulnflow.db"),
        "VULNFLOW_DB": str(volume / "legacy-vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(volume / "vulnflow-coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(volume / "projects" / "default" / "evidence"),
        "VULNFLOW_RECOVERY_DIR": str(volume / "projects" / "default" / "recovery"),
        "VULNFLOW_EXPORT_DIR": str(volume / "projects" / "default" / "exports"),
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({
            "deployment-operator": {
                "token": "deployment-rehearsal-operator-token-72-0-6",
                "role": "operator",
                "projects": ["default"],
            },
            "deployment-admin": {
                "token": "deployment-rehearsal-admin-token-72-0-14",
                "role": "admin",
                "projects": ["default"],
            },
        }),
        "VULNFLOW_CURSOR_SIGNING_KEY": "deployment-rehearsal-cursor-signing-key-72-0-6",
        "VULNFLOW_AUDIT_SIGNING_KEY": "deployment-rehearsal-audit-signing-key-72-0-6",
        "VULNFLOW_BACKUP_SIGNING_KEY": "deployment-rehearsal-backup-signing-key-72-0-6",
        "VULNFLOW_JOB_WORKER_ENABLED": "1",
        "VULNFLOW_JOB_WORKER_INTERVAL_SECONDS": "1",
        "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
        "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "1",
        "VULNFLOW_INSTANCE_ID": f"deployment-rehearsal-{cycle}",
        "VULNFLOW_COOKIE_SECURE": "0",
    })
    return env


def _process_uid(pid: int) -> int | None:
    if os.name != "posix":
        return None
    status = Path(f"/proc/{pid}/status")
    if not status.is_file():
        return None
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    return None


def _wait_ready(base_url: str, process: subprocess.Popen[Any], log_path: Path, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"deployment process exited before readiness: {process.returncode}\n{log[-4000:]}")
        try:
            response = requests.get(base_url + "/health/ready", timeout=1)
            if response.status_code == 200:
                return
            last_error = f"status={response.status_code}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(0.2)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"deployment process did not become ready ({last_error})\n{log[-4000:]}")


def _terminate_process(process: subprocess.Popen[Any], timeout_seconds: float = 12) -> tuple[int, int]:
    started = time.monotonic()
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)
        raise RuntimeError("deployment process did not stop within the SIGTERM deadline")
    duration_ms = int((time.monotonic() - started) * 1000)
    if return_code not in {0, -int(signal.SIGTERM)}:
        raise RuntimeError(f"deployment process returned an unexpected code after SIGTERM: {return_code}")
    return return_code, duration_ms


def _launch_cycle(
    source: Path,
    volume: Path,
    identity: RuntimeIdentity,
    cycle: int,
    *,
    expect_persisted: bool,
) -> dict[str, Any]:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    log_path = volume / f"uvicorn-cycle-{cycle}.log"
    command = [
        *identity.command_prefix,
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "info",
    ]
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            cwd=source,
            env=_deployment_environment(volume, cycle),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=(os.name == "posix"),
            preexec_fn=_preexec_for_identity(identity),
        )
    result: dict[str, Any] = {"cycle": cycle, "pid": process.pid, "port": port}
    try:
        _wait_ready(base_url, process, log_path)
        result["effective_uid"] = _process_uid(process.pid)
        result["ready_status"] = requests.get(base_url + "/health/ready", timeout=3).status_code
        result["live_status"] = requests.get(base_url + "/health/live", timeout=3).status_code
        result["anonymous_root_status"] = requests.get(base_url + "/", timeout=3).status_code
        result["authenticated_root_status"] = requests.get(
            base_url + "/",
            headers=_bearer("deployment-rehearsal-admin-token-72-0-14"),
            timeout=3,
        ).status_code

        finding = requests.get(
            base_url + "/api/v1/findings/DEPLOY-1",
            headers=_bearer("deployment-rehearsal-operator-token-72-0-6"),
            timeout=3,
        )
        result["finding_before_status"] = finding.status_code
        if expect_persisted:
            result["persistence_verified"] = finding.status_code == 200 and finding.json().get("scanner_source") == "deployment-rehearsal"
        else:
            payload = b"finding_id,product,cve_id,cvss\nDEPLOY-1,Deployment Rehearsal,CVE-2026-72005,8.7\n"
            imported = requests.post(
                base_url + "/api/v1/imports/csv?scanner_source=deployment-rehearsal",
                headers=_bearer("deployment-rehearsal-operator-token-72-0-6"),
                files={"file": ("deployment.csv", payload, "text/csv")},
                timeout=8,
            )
            result["import_status"] = imported.status_code
            detail = requests.get(
                base_url + "/api/v1/findings/DEPLOY-1",
                headers=_bearer("deployment-rehearsal-operator-token-72-0-6"),
                timeout=3,
            )
            result["finding_after_status"] = detail.status_code
            result["persistence_verified"] = detail.status_code == 200
    finally:
        if process.poll() is None:
            return_code, duration_ms = _terminate_process(process)
            result["return_code"] = return_code
            result["shutdown_ms"] = duration_ms
        else:
            result["return_code"] = process.returncode
            result["shutdown_ms"] = 0
    result["log_tail"] = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
    return result


def _sqlite_state(database: Path) -> dict[str, Any]:
    with sqlite3.connect(database) as conn:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        finding_count = int(conn.execute("SELECT COUNT(*) FROM findings WHERE finding_id='DEPLOY-1'").fetchone()[0])
    return {
        "integrity_check": integrity,
        "schema_version": schema_version,
        "persisted_finding_count": finding_count,
    }


def _docker_engine() -> dict[str, Any]:
    executable = shutil.which("docker")
    if not executable:
        return {"available": False, "version": None}
    completed = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=10, check=False)
    return {
        "available": completed.returncode == 0,
        "version": (completed.stdout or completed.stderr).strip() or None,
    }


def run_rehearsal(root: Path = ROOT, *, cycles: int = 2, keep_temp: bool = False) -> dict[str, Any]:
    if cycles < 2:
        raise ValueError("at least two cycles are required to verify persistent restart behavior")
    static_contract = validate_container_contract(root)
    identity = _runtime_identity()
    temp_dir = Path(tempfile.mkdtemp(prefix="vulnflow_deployment_rehearsal_"))
    temp_dir.chmod(0o755)
    source = temp_dir / "app"
    volume = temp_dir / "data"
    try:
        _copy_readonly_source(root, source)
        _prepare_volume(volume, identity)
        source_digest_before = _tree_digest(source)
        source_writable_files = [
            path.relative_to(source).as_posix()
            for path in source.rglob("*")
            if path.is_file() and bool(path.stat().st_mode & 0o222)
        ]

        cycle_results = [
            _launch_cycle(source, volume, identity, cycle, expect_persisted=(cycle > 1))
            for cycle in range(1, cycles + 1)
        ]
        source_digest_after = _tree_digest(source)
        database = volume / "projects" / "default" / "vulnflow.db"
        sqlite_state = _sqlite_state(database)
        database_stat = database.stat()

        checks = {
            **{f"static_{name}": passed for name, passed in static_contract.items()},
            "readonly_source_files": not source_writable_files,
            "source_tree_unchanged": source_digest_before == source_digest_after,
            "nonroot_process_identity": all(
                item.get("effective_uid") == identity.expected_uid
                for item in cycle_results
                if identity.expected_uid is not None
            ),
            "readiness_all_cycles": all(item.get("ready_status") == 200 and item.get("live_status") == 200 for item in cycle_results),
            "anonymous_access_denied": all(item.get("anonymous_root_status") == 401 for item in cycle_results),
            "configured_authentication_works": all(item.get("authenticated_root_status") == 200 for item in cycle_results),
            "persistent_volume_restart": all(bool(item.get("persistence_verified")) for item in cycle_results),
            "graceful_sigterm": all(
                item.get("return_code") in {0, -int(signal.SIGTERM)}
                and int(item.get("shutdown_ms") or 0) <= 12000
                and "Application shutdown complete." in str(item.get("log_tail") or "")
                for item in cycle_results
            ),
            "database_owned_by_runtime_uid": identity.expected_uid is None or database_stat.st_uid == identity.expected_uid,
            "sqlite_integrity": sqlite_state["integrity_check"] == "ok",
            "schema_version": sqlite_state["schema_version"] == EXPECTED_SCHEMA_VERSION,
            "persisted_finding_singleton": sqlite_state["persisted_finding_count"] == 1,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        result = {
            "format": "vulnflow-container-deployment-rehearsal/1",
            "version": (root / "VERSION").read_text(encoding="utf-8").strip(),
            "status": "PASS" if not failed else "FAIL",
            "checks_passed": sum(1 for passed in checks.values() if passed),
            "checks_total": len(checks),
            "failed_checks": failed,
            "checks": checks,
            "identity": {
                "mode": identity.mode,
                "expected_uid": identity.expected_uid,
                "expected_gid": identity.expected_gid,
            },
            "cycles": cycle_results,
            "sqlite": sqlite_state,
            "source_digest_before": source_digest_before,
            "source_digest_after": source_digest_after,
            "source_writable_files": source_writable_files,
            "database_uid": database_stat.st_uid if os.name == "posix" else None,
            "database_gid": database_stat.st_gid if os.name == "posix" else None,
            "docker_engine": _docker_engine(),
            "limitations": [
                "This is a container-equivalent process rehearsal, not an actual Docker image build or docker compose run.",
                "Layer construction, Docker volume drivers, container networking, and engine health status were not exercised when Docker is unavailable.",
            ],
        }
        if failed:
            raise RuntimeError("container deployment rehearsal failed: " + ", ".join(failed))
        return result
    finally:
        if keep_temp:
            print(f"temporary rehearsal directory retained: {temp_dir}", file=sys.stderr)
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _text_report(result: dict[str, Any]) -> str:
    lines = [
        f"VulnFlow {result['version']} container deployment rehearsal",
        "",
        f"status: {result['status']}",
        f"checks: {result['checks_passed']}/{result['checks_total']}",
        f"identity_mode: {result['identity']['mode']}",
        f"expected_uid: {result['identity']['expected_uid']}",
        f"cycles: {len(result['cycles'])}",
        f"sqlite_integrity: {result['sqlite']['integrity_check']}",
        f"schema_version: {result['sqlite']['schema_version']}",
        f"persisted_finding_count: {result['sqlite']['persisted_finding_count']}",
        f"docker_engine_available: {result['docker_engine']['available']}",
        "",
        "cycle_results:",
    ]
    for item in result["cycles"]:
        lines.append(
            f"- cycle={item['cycle']} uid={item.get('effective_uid')} ready={item.get('ready_status')} "
            f"anonymous={item.get('anonymous_root_status')} authenticated={item.get('authenticated_root_status')} "
            f"persisted={item.get('persistence_verified')} shutdown_ms={item.get('shutdown_ms')}"
        )
    lines.extend(["", "limitations:"])
    lines.extend(f"- {item}" for item in result["limitations"])
    return "\n".join(lines) + "\n"


def write_reports(result: dict[str, Any], json_path: Path, text_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    text_path.write_text(_text_report(result), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse VulnFlow's non-root persistent container deployment contract.")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--json-output", type=Path, default=REPORT_JSON)
    parser.add_argument("--text-output", type=Path, default=REPORT_TEXT)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()
    result = run_rehearsal(cycles=args.cycles, keep_temp=args.keep_temp)
    write_reports(result, args.json_output, args.text_output)
    print(_text_report(result), end="")


if __name__ == "__main__":
    main()
