from __future__ import annotations

import json
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import app.main as main
from app.core.context import get_application_context
from app.core.storage import acquire_cluster_lease, active_cluster_lease, count_cluster_write_activities



def build_app(root: Path, name: str, token: str):
    return main.create_app(
        setting_overrides={
            "DB_PATH": root / f"{name}.sqlite3",
            "COORDINATION_DB_ENV": str(root / f"{name}-coordination.sqlite3"),
            "INSTANCE_ID": f"smoke-{name}",
            "AUTH_USERS_JSON": "",
            "AUTH_API_TOKENS_JSON": json.dumps({name: {"token": token, "role": "admin", "projects": "*"}}),
            "JOB_WORKER_ENABLED": False,
            "MAINTENANCE_INTERVAL_MINUTES": 0,
            "WEBHOOKS_JSON": "",
            "BACKUP_INTERVAL_HOURS": 0,
            "CLUSTER_COORDINATION_ENABLED": True,
        }
    )


def main_smoke() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="vulnflow-operation-guard-") as temp_name:
        temp = Path(temp_name)
        token_a, token_b = "a" * 32, "b" * 32
        app_a = build_app(temp, "a", token_a)
        app_b = build_app(temp, "b", token_b)
        context_a = get_application_context(app_a)
        context_b = get_application_context(app_b)
        guard_a = context_a.operation_guard
        guard_b = context_b.operation_guard
        assert guard_a is not None and guard_b is not None and guard_a is not guard_b

        with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
            lease = acquire_cluster_lease(
                guard_a.coordination_db_path,
                lease_name=str(context_a.get("RESTORE_LEASE_NAME")),
                holder_id="smoke-restore-owner",
                ttl_seconds=60,
            )
            assert lease is not None
            blocked = client_a.post(
                "/api/v1/exports/storage/cleanup",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            allowed = client_b.post(
                "/api/v1/exports/storage/cleanup",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            assert blocked.status_code == 503
            assert allowed.status_code == 200
            assert count_cluster_write_activities(guard_a.coordination_db_path) == 0
            assert count_cluster_write_activities(guard_b.coordination_db_path) == 0

        lease_name = "exclusive:operation-guard-smoke"
        with guard_b.exclusive_operation(lease_name, "operation guard smoke") as owned:
            assert owned and owned["holder_id"] == "smoke-b"
            assert active_cluster_lease(guard_b.coordination_db_path, lease_name)
            assert active_cluster_lease(guard_a.coordination_db_path, lease_name) is None

        return {
            "version": "72.0.93",
            "blocked_app_status": blocked.status_code,
            "independent_app_status": allowed.status_code,
            "router_guards_distinct": guard_a is not guard_b,
            "exclusive_lease_isolated": True,
            "write_activities_after_requests": {
                "a": count_cluster_write_activities(guard_a.coordination_db_path),
                "b": count_cluster_write_activities(guard_b.coordination_db_path),
            },
        }


if __name__ == "__main__":
    result = main_smoke()
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "operation_guard_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    text = "\n".join(
        [
            "VulnFlow 72.0.93 context-bound operation guard verification",
            "",
            f"restore barrier isolated: {'PASS' if result['blocked_app_status'] == 503 and result['independent_app_status'] == 200 else 'FAIL'}",
            f"router guards distinct: {'PASS' if result['router_guards_distinct'] else 'FAIL'}",
            f"exclusive lease isolated: {'PASS' if result['exclusive_lease_isolated'] else 'FAIL'}",
            f"write activity cleanup: {'PASS' if result['write_activities_after_requests'] == {'a': 0, 'b': 0} else 'FAIL'}",
        ]
    ) + "\n"
    (reports / "operation_guard_verification.txt").write_text(text, encoding="utf-8")
    print(text, end="")
