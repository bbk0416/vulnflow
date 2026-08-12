from __future__ import annotations

import ast
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import CURRENT_APP_VERSION, init_db
from app.core.architecture import build_architecture_report
from app.repositories import webhook_delivery, webhook_queue, webhooks


def main() -> int:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    importers: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "app/repositories/webhooks.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.repositories.webhooks":
                importers.append(relative)
            elif isinstance(node, ast.Import) and any(
                alias.name == "app.repositories.webhooks" for alias in node.names
            ):
                importers.append(relative)

    checks: dict[str, bool] = {
        "version_72_0_7": CURRENT_APP_VERSION == "72.0.81",
        "facade_enqueue_identity": webhooks.enqueue_webhook_events is webhook_queue.enqueue_webhook_events,
        "facade_claim_identity": webhooks.list_due_webhook_events is webhook_delivery.list_due_webhook_events,
        "facade_record_identity": webhooks.record_webhook_delivery is webhook_delivery.record_webhook_delivery,
        "internal_facade_importers_zero": not importers,
        "queue_does_not_import_delivery": "app.repositories.webhook_delivery" not in set(
            by_path["app/repositories/webhook_queue.py"]["internal_imports"]
        ),
        "delivery_uses_queue_read_model": "app.repositories.webhook_queue" in set(
            by_path["app/repositories/webhook_delivery.py"]["internal_imports"]
        ),
        "architecture_pass": architecture["status"] == "PASS",
    }

    with tempfile.TemporaryDirectory(prefix="vulnflow-webhook-boundary-") as tmp:
        db = Path(tmp) / "webhooks.sqlite3"
        init_db(db)
        ids = webhook_queue.enqueue_webhook_events(
            db,
            endpoint_names=["smoke"],
            event_type="finding.updated",
            payload={"finding_id": "V71-SMOKE"},
            actor="smoke",
        )
        claimed = webhook_delivery.list_due_webhook_events(db)
        delivered = webhook_delivery.record_webhook_delivery(
            db,
            event_id=ids[0],
            delivered=True,
            response_status=202,
            error="",
        )
        checks["queue_round_trip"] = len(ids) == 1 and len(claimed) == 1
        checks["delivery_round_trip"] = delivered.get("status") == "DELIVERED"

    payload = {
        "title": "VulnFlow 72.0.81 webhook repository boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "internal_facade_importers": sorted(set(importers)),
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "webhook_repository_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        payload["title"],
        f"version: {CURRENT_APP_VERSION}",
        "",
        *[f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()],
        "",
        f"summary: {payload['passed']}/{payload['total']}",
    ]
    (reports / "webhook_repository_boundary_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
