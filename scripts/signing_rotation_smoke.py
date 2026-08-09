from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def env_for(db: Path, keys: dict[str, str], audit_id: str, backup_id: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "VULNFLOW_DB": str(db),
        "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
        "VULNFLOW_JOB_WORKER_ENABLED": "0",
        "VULNFLOW_WEBHOOK_INTERVAL_SECONDS": "0",
        "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
        "VULNFLOW_BACKUP_INTERVAL_HOURS": "0",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({
            "rotation-admin": {"token": "rotation-admin-token-123456", "role": "admin", "projects": "*"}
        }),
        "VULNFLOW_SIGNING_KEYS_JSON": json.dumps(keys),
        "VULNFLOW_AUDIT_ACTIVE_KEY_ID": audit_id,
        "VULNFLOW_BACKUP_ACTIVE_KEY_ID": backup_id,
        "VULNFLOW_AUDIT_REQUIRE_SIGNATURE": "1",
        "VULNFLOW_BACKUP_REQUIRE_SIGNATURE": "1",
        "VULNFLOW_AUDIT_SIGNING_KEY": "",
        "VULNFLOW_BACKUP_SIGNING_KEY": "",
    })
    return env


def start_server(env: dict[str, str], port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def wait_ready(process: subprocess.Popen[str], port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"server exited early: {process.returncode}\n{output}")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health/ready", timeout=0.5).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise TimeoutError("server did not become ready")


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    old_keys = {
        "audit-old": "rotation-old-audit-secret-long",
        "backup-old": "rotation-old-backup-secret-long",
    }
    all_keys = old_keys | {
        "audit-new": "rotation-new-audit-secret-long",
        "backup-new": "rotation-new-backup-secret-long",
    }
    bearer = {"Authorization": "Bearer rotation-admin-token-123456"}

    with tempfile.TemporaryDirectory(prefix="vulnflow_key_rotation_") as temp_name:
        root = Path(temp_name)
        db = root / "rotation.sqlite3"
        bundle = root / "old-key-bundle.zip"

        first = start_server(env_for(db, old_keys, "audit-old", "backup-old"), free_port())
        first_port = int(first.args[-2]) if False else None
        # args layout is stable but retain the selected port separately.
        first_port = int(first.args[first.args.index("--port") + 1])
        try:
            wait_ready(first, first_port)
            with httpx.Client(timeout=10) as client:
                integrity = client.get(f"http://127.0.0.1:{first_port}/api/v1/audit/integrity", headers=bearer)
                assert integrity.status_code == 200
                assert integrity.json()["checkpoints"][-1]["key_id"] == "audit-old"
                exported = client.get(f"http://127.0.0.1:{first_port}/export/recovery-bundle.zip", headers=bearer)
                assert exported.status_code == 200
                bundle.write_bytes(exported.content)
        finally:
            stop(first)

        second_port = free_port()
        second = start_server(env_for(db, all_keys, "audit-new", "backup-new"), second_port)
        try:
            wait_ready(second, second_port)
            with httpx.Client(timeout=10) as client:
                integrity = client.get(f"http://127.0.0.1:{second_port}/api/v1/audit/integrity", headers=bearer)
                assert integrity.status_code == 200
                key_ids = [item.get("key_id") for item in integrity.json()["checkpoints"]]
                assert "audit-old" in key_ids and "audit-new" in key_ids
                with bundle.open("rb") as handle:
                    validated = client.post(
                        f"http://127.0.0.1:{second_port}/api/v1/recovery/validate",
                        headers=bearer,
                        files={"file": (bundle.name, handle, "application/zip")},
                    )
                assert validated.status_code == 200, validated.text
                assert validated.json()["signing_key_id"] == "backup-old"
                usage = client.get(f"http://127.0.0.1:{second_port}/api/v1/system/signing-keys", headers=bearer)
                assert usage.status_code == 200
                by_id = {item["key_id"]: item for item in usage.json()["usage"]["items"]}
                assert by_id["audit-old"]["audit_checkpoint_refs"] >= 1
        finally:
            stop(second)

        only_new = {"audit-new": all_keys["audit-new"], "backup-new": all_keys["backup-new"]}
        third_port = free_port()
        third = start_server(env_for(db, only_new, "audit-new", "backup-new"), third_port)
        try:
            deadline = time.time() + 20
            health_payload = None
            ready_status = None
            while time.time() < deadline:
                if third.poll() is not None:
                    output = third.stdout.read() if third.stdout else ""
                    raise RuntimeError(f"recovery-mode server exited unexpectedly: {third.returncode}\n{output}")
                try:
                    health = httpx.get(f"http://127.0.0.1:{third_port}/health", timeout=0.5)
                    ready = httpx.get(f"http://127.0.0.1:{third_port}/health/ready", timeout=0.5)
                    if health.status_code == 200:
                        health_payload = health.json()
                        ready_status = ready.status_code
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            assert health_payload is not None, "recovery-mode health endpoint did not become available"
            assert health_payload.get("status") == "degraded", health_payload
            assert health_payload.get("recovery_mode", {}).get("active") is True, health_payload
            assert ready_status == 503, ready_status
        finally:
            stop(third)

    print("old key checkpoint: verified")
    print("new active key checkpoint: created")
    print("old recovery bundle under new keyring: verified")
    print("referenced old key removal: read-only recovery mode entered")
    print("signing rotation smoke passed: 4 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
