from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="vulnflow_uvicorn_") as temp_dir:
        env = os.environ.copy()
        data_dir = Path(temp_dir) / "data"
        project_root = data_dir / "projects" / "default"
        env.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "VULNFLOW_DATA_DIR": str(data_dir),
            "VULNFLOW_DB": str(data_dir / "legacy.sqlite3"),
            "VULNFLOW_CONTROL_DB": str(data_dir / "control.sqlite3"),
            "VULNFLOW_PROJECTS_DIR": str(data_dir / "projects"),
            "VULNFLOW_DEFAULT_PROJECT_ROOT": str(project_root),
            "VULNFLOW_DEFAULT_PROJECT_DB": str(project_root / "vulnflow.sqlite3"),
            "VULNFLOW_COORDINATION_DB": str(data_dir / "coordination.sqlite3"),
            "VULNFLOW_EVIDENCE_DIR": str(project_root / "evidence"),
            "VULNFLOW_RECOVERY_DIR": str(project_root / "recovery"),
            "VULNFLOW_BACKUP_SIGNING_KEY": "uvicorn-backup-signing-key",
            "VULNFLOW_BACKUP_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_AUDIT_SIGNING_KEY": "uvicorn-audit-signing-key",
            "VULNFLOW_AUDIT_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_API_TOKENS_JSON": json.dumps({
                "viewer-api": {"token": "uvicorn-viewer-token-1234567", "role": "viewer", "projects": "*"},
                "ops": {"token": "uvicorn-operator-token-12345", "role": "operator", "projects": "*"},
                "approval": {"token": "uvicorn-approval-token-1234", "role": "approver", "projects": "*"},
                "admin-api": {"token": "uvicorn-admin-token-123456", "role": "admin", "projects": "*"},
            }),
        })
        stdout_log_path = Path(temp_dir) / "uvicorn.stdout.log"
        stderr_log_path = Path(temp_dir) / "uvicorn.stderr.log"
        stdout_log = stdout_log_path.open("w+", encoding="utf-8")
        stderr_log = stderr_log_path.open("w+", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=ROOT,
            env=env,
            stdout=stdout_log,
            stderr=stderr_log,
            text=True,
        )
        results: list[str] = []
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    response = requests.get(base + "/health/ready", timeout=1)
                    if response.status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.2)
            else:
                raise SystemExit("uvicorn did not become ready")

            checks = [
                ("anonymous root", requests.get(base + "/", timeout=3).status_code, 401),
                ("viewer root", requests.get(base + "/", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("viewer upload", requests.get(base + "/upload", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 403),
                ("viewer policies", requests.get(base + "/policies", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("viewer jobs", requests.get(base + "/jobs", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("viewer assets", requests.get(base + "/assets", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("viewer exposure groups", requests.get(base + "/exposure-groups", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("viewer campaigns", requests.get(base + "/campaigns", headers=bearer("uvicorn-viewer-token-1234567"), timeout=3).status_code, 200),
                ("assets api", requests.get(base + "/api/v1/assets", headers=bearer("uvicorn-operator-token-12345"), timeout=3).status_code, 200),
                ("admin system", requests.get(base + "/system", headers=bearer("uvicorn-admin-token-123456"), timeout=3).status_code, 200),
                ("admin cluster", requests.get(base + "/cluster", headers=bearer("uvicorn-admin-token-123456"), timeout=3).status_code, 200),
                ("cluster api", requests.get(base + "/api/v1/system/cluster", headers=bearer("uvicorn-admin-token-123456"), timeout=3).status_code, 200),
                ("audit integrity", requests.get(base + "/api/v1/audit/integrity", headers=bearer("uvicorn-approval-token-1234"), timeout=3).status_code, 200),
                ("bearer summary", requests.get(base + "/api/v1/summary", headers=bearer("uvicorn-operator-token-12345"), timeout=3).status_code, 200),
                ("live", requests.get(base + "/health/live", timeout=3).status_code, 200),
                ("ready", requests.get(base + "/health/ready", timeout=3).status_code, 200),
            ]
            for name, actual, expected in checks:
                results.append(f"{name}: {actual}")
                if actual != expected:
                    raise SystemExit(f"{name}: expected {expected}, got {actual}")

            checkpoint = requests.post(
                base + "/api/v1/audit/checkpoints", headers=bearer("uvicorn-admin-token-123456"), timeout=3,
            )
            results.append(f"audit checkpoint: {checkpoint.status_code}")
            if checkpoint.status_code != 200 or not checkpoint.json().get("signed"):
                raise SystemExit(f"audit checkpoint failed: {checkpoint.text}")

            recovery = requests.get(
                base + "/export/recovery-bundle.zip", headers=bearer("uvicorn-admin-token-123456"), timeout=10,
            )
            results.append(f"recovery export: {recovery.status_code}")
            if recovery.status_code != 200 or not recovery.content.startswith(b"PK"):
                raise SystemExit("recovery export failed")
            recovery_check = requests.post(
                base + "/api/v1/recovery/validate", headers=bearer("uvicorn-admin-token-123456"),
                files={"file": ("recovery.zip", recovery.content, "application/zip")}, timeout=10,
            )
            results.append(f"recovery validate: {recovery_check.status_code}")
            if recovery_check.status_code != 200 or not recovery_check.json().get("valid"):
                raise SystemExit(f"recovery validate failed: {recovery_check.text}")

            payload = b"finding_id,product,cve_id,cvss\nUV-1,Uvicorn Product,CVE-2026-60001,8.4\n"
            imported = requests.post(
                base + "/api/v1/imports/csv?scanner_source=uvicorn-smoke",
                headers=bearer("uvicorn-operator-token-12345"),
                files={"file": ("uvicorn.csv", payload, "text/csv")},
                timeout=5,
            )
            results.append(f"api import: {imported.status_code}")
            if imported.status_code != 200:
                raise SystemExit(f"api import failed: {imported.text}")
            queued_job = requests.post(
                base + "/api/v1/jobs/queue/RESCORE_ALL",
                headers=bearer("uvicorn-operator-token-12345"), timeout=3,
            )
            results.append(f"job queue: {queued_job.status_code}")
            if queued_job.status_code != 200:
                raise SystemExit(f"job queue failed: {queued_job.text}")
            job_id = queued_job.json()["job_id"]
            deadline = time.time() + 8
            job_state = None
            while time.time() < deadline:
                job_state = requests.get(
                    base + f"/api/v1/jobs/{job_id}",
                    headers=bearer("uvicorn-operator-token-12345"), timeout=3,
                )
                if job_state.status_code == 200 and job_state.json().get("status") == "SUCCEEDED":
                    break
                time.sleep(0.2)
            results.append(f"job completed: {job_state.status_code if job_state else 0}")
            if not job_state or job_state.status_code != 200 or job_state.json().get("status") != "SUCCEEDED":
                raise SystemExit("background job did not complete")

            item = requests.get(base + "/api/v1/findings/UV-1", headers=bearer("uvicorn-operator-token-12345"), timeout=3)
            results.append(f"api detail: {item.status_code}")
            if item.status_code != 200 or item.json().get("scanner_source") != "uvicorn-smoke":
                raise SystemExit("uvicorn API detail failed")

            load_targets = [
                ("/health/live", None),
                ("/health/ready", None),
                ("/api/v1/summary", bearer("uvicorn-operator-token-12345")),
                ("/api/v1/assets", bearer("uvicorn-operator-token-12345")),
            ]

            def load_request(index: int) -> tuple[int, str, int]:
                path, headers = load_targets[index % len(load_targets)]
                response = requests.get(base + path, headers=headers, timeout=5)
                return index, path, response.status_code

            load_started = time.perf_counter()
            load_failures: list[tuple[int, str, int]] = []
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(load_request, index) for index in range(320)]
                for future in as_completed(futures):
                    index, path, status = future.result()
                    if status != 200:
                        load_failures.append((index, path, status))
            load_elapsed = time.perf_counter() - load_started
            results.append(f"bounded http reads: {320 - len(load_failures)}/320 in {load_elapsed:.3f}s")
            if load_failures:
                raise SystemExit(f"bounded HTTP read load failed: {load_failures[:10]}")
            policy = yaml.safe_load((ROOT / "rules" / "prioritization_policy.yml").read_text(encoding="utf-8"))
            policy["version"] = "2.2.0-uvicorn"
            policy["name"] = "Uvicorn smoke candidate"
            policy["weights"]["internet_exposed"] = int(policy["weights"]["internet_exposed"]) + 2
            created_policy = requests.post(
                base + "/api/v1/policies", headers=bearer("uvicorn-admin-token-123456"),
                json={"content_yaml": yaml.safe_dump(policy, allow_unicode=True, sort_keys=False), "notes": "uvicorn"},
                timeout=5,
            )
            results.append(f"policy create: {created_policy.status_code}")
            if created_policy.status_code != 200:
                raise SystemExit(f"policy create failed: {created_policy.text}")
            policy_id = created_policy.json()["policy_id"]
            activation = requests.post(
                base + f"/api/v1/policies/{policy_id}/activation-requests",
                headers=bearer("uvicorn-admin-token-123456"), json={"reason": "uvicorn activation"}, timeout=5,
            )
            results.append(f"policy request: {activation.status_code}")
            if activation.status_code != 200:
                raise SystemExit(f"policy request failed: {activation.text}")
            approved = requests.post(
                base + f"/api/v1/policy-activation-requests/{activation.json()['request_id']}/decision",
                headers=bearer("uvicorn-approval-token-1234"),
                json={"decision": "APPROVED", "decision_note": "uvicorn approved"}, timeout=5,
            )
            results.append(f"policy approve: {approved.status_code}")
            if approved.status_code != 200:
                raise SystemExit(f"policy approval failed: {approved.text}")
        finally:
            had_exception = sys.exc_info()[0] is not None
            pre_shutdown_returncode = process.poll()
            if pre_shutdown_returncode is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            stdout_log.flush()
            stderr_log.flush()
            stdout_log.close()
            stderr_log.close()
            stdout = stdout_log_path.read_text(encoding="utf-8", errors="replace")
            stderr = stderr_log_path.read_text(encoding="utf-8", errors="replace")
            if had_exception:
                if stdout.strip():
                    print("uvicorn stdout:\n" + stdout[-12000:], file=sys.stderr)
                if stderr.strip():
                    print("uvicorn stderr:\n" + stderr[-12000:], file=sys.stderr)
            elif pre_shutdown_returncode is not None:
                raise SystemExit(
                    f"uvicorn exited unexpectedly before smoke cleanup: "
                    f"{pre_shutdown_returncode}\n{stdout}\n{stderr}"
                )

        for line in results:
            print(line)
        print(f"uvicorn smoke passed: {len(results)} checks")


if __name__ == "__main__":
    main()
