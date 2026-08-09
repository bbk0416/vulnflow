from __future__ import annotations

import base64
import json
import os
import signal
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import acquire_cluster_lease, init_coordination_db, release_cluster_lease

TOKEN = "cluster-smoke-admin-token-0123456789"


def _request(url: str, *, method: str = "GET", token: str | None = None, data: bytes | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, method=method, headers=headers)
    try:
        with urlopen(request, timeout=3) as response:
            body = response.read()
            return response.status, json.loads(body.decode("utf-8")) if body else {}
    except HTTPError as exc:
        body = exc.read()
        try:
            parsed = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            parsed = {"raw": body.decode("utf-8", errors="replace")}
        return exc.code, parsed


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_ready(
    port: int,
    *,
    process: subprocess.Popen,
    expected_instance_id: str,
    timeout: float = 20.0,
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            log_path = getattr(process, "_vulnflow_log_path", None)
            details = ""
            if log_path and Path(log_path).exists():
                details = Path(log_path).read_text(errors="replace")[-2000:]
            raise RuntimeError(
                f"instance {expected_instance_id} exited before readiness on port {port}: {details}"
            )
        try:
            status, _ = _request(f"http://127.0.0.1:{port}/health/ready")
            if status == 200:
                cluster_status, cluster = _request(
                    f"http://127.0.0.1:{port}/api/v1/system/cluster", token=TOKEN
                )
                if (
                    cluster_status == 200
                    and cluster.get("instance_id") == expected_instance_id
                ):
                    return
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(0.2)
    raise RuntimeError(
        f"instance {expected_instance_id} on port {port} did not become ready"
    )


def _start(port: int, instance_id: str, db: Path, coord: Path, log: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT),
        "VULNFLOW_DB": str(db),
        "VULNFLOW_COORDINATION_DB": str(coord),
        "VULNFLOW_INSTANCE_ID": instance_id,
        "VULNFLOW_INSTANCE_HEARTBEAT_SECONDS": "2",
        "VULNFLOW_INSTANCE_TTL_SECONDS": "6",
        "VULNFLOW_SCHEDULER_LEASE_SECONDS": "6",
        "VULNFLOW_EXCLUSIVE_OPERATION_LEASE_SECONDS": "60",
        "VULNFLOW_JOB_WORKER_ENABLED": "0",
        "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
        "VULNFLOW_BACKUP_INTERVAL_HOURS": "0",
        "VULNFLOW_WEBHOOKS_JSON": "",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({"admin": {"token": TOKEN, "role": "admin", "projects": "*"}}),
        "VULNFLOW_LOG_LEVEL": "WARNING",
    })
    handle = log.open("wb")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT,
        start_new_session=(os.name != "nt"),
    )
    process._vulnflow_log_handle = handle  # type: ignore[attr-defined]
    process._vulnflow_log_path = log  # type: ignore[attr-defined]
    return process


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait(timeout=5)
    handle = getattr(process, "_vulnflow_log_handle", None)
    if handle:
        handle.close()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="vulnflow_cluster_smoke_") as temp_name:
        temp = Path(temp_name)
        db = temp / "vulnflow.sqlite3"
        coord = temp / "coordination.sqlite3"
        init_coordination_db(coord)
        ports = [_free_port(), _free_port()]
        while ports[1] == ports[0]:
            ports[1] = _free_port()
        instance_ids = ["smoke-node-a", "smoke-node-b"]
        processes = [
            _start(ports[0], instance_ids[0], db, coord, temp / "node-a.log"),
            _start(ports[1], instance_ids[1], db, coord, temp / "node-b.log"),
        ]
        try:
            for port, process, instance_id in zip(ports, processes, instance_ids):
                _wait_ready(
                    port, process=process, expected_instance_id=instance_id
                )
            snapshots = {}
            stable_deadline = time.time() + 12
            while time.time() < stable_deadline:
                snapshots = {}
                for port in ports:
                    status, body = _request(
                        f"http://127.0.0.1:{port}/api/v1/system/cluster", token=TOKEN
                    )
                    if status != 200:
                        raise AssertionError((port, status, body))
                    snapshots[port] = body
                lease_views = {
                    (body.get("scheduler_lease_holder_id"), body.get("scheduler_lease_fencing_token"))
                    for body in snapshots.values()
                }
                leaders = [port for port, body in snapshots.items() if body["is_scheduler_leader"]]
                if len(lease_views) == 1 and len(leaders) == 1:
                    break
                time.sleep(0.25)
            else:
                raise AssertionError(f"cluster did not reach one stable leader: {snapshots}")
            leader_port = leaders[0]
            leader_index = ports.index(leader_port)
            follower_port = ports[1 - leader_index]
            _stop(processes[leader_index])

            deadline = time.time() + 15
            promoted = False
            follower_snapshot = {}
            while time.time() < deadline:
                status, follower_snapshot = _request(
                    f"http://127.0.0.1:{follower_port}/api/v1/system/cluster", token=TOKEN
                )
                if status == 200 and follower_snapshot.get("is_scheduler_leader"):
                    promoted = True
                    break
                time.sleep(0.5)
            if not promoted:
                raise AssertionError(f"follower was not promoted: {follower_snapshot}")

            lock = acquire_cluster_lease(
                coord, lease_name="exclusive:restore", holder_id="smoke-restore-controller",
                ttl_seconds=30, purpose="cluster smoke restore lock",
            )
            if not lock:
                raise AssertionError("failed to acquire restore lock")
            status, body = _request(
                f"http://127.0.0.1:{follower_port}/api/v1/jobs/queue/RESCORE_ALL",
                method="POST", token=TOKEN, data=b"{}",
            )
            if status != 503:
                raise AssertionError((status, body))
            release_cluster_lease(
                coord, lease_name="exclusive:restore", holder_id="smoke-restore-controller",
                fencing_token=int(lock["fencing_token"]),
            )

            output = {
                "initial_leader_port": leader_port,
                "promoted_follower_port": follower_port,
                "fencing_token_after_failover": follower_snapshot.get("scheduler_fencing_token"),
                "restore_lock_write_status": status,
                "registered_instances": len(follower_snapshot.get("instances", [])),
            }
            print(json.dumps(output, ensure_ascii=False, indent=2))
            return 0
        finally:
            for process in processes:
                _stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
