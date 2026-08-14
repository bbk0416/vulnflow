from __future__ import annotations

import json
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import database_schema, storage
from app.core.architecture import build_architecture_report
from app.repositories import campaigns
from app.services import database_lifecycle



def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow-storage-modularization-") as temp:
        db = Path(temp) / "vulnflow.db"
        storage.init_db(db)
        report = build_architecture_report(ROOT)
        by_path = {item["path"]: item for item in report["modules"]}
        checks = [
            ("version_72_0_7", storage.CURRENT_APP_VERSION == "72.0.87"),
            ("schema_42", storage.CURRENT_SCHEMA_VERSION == 46),
            ("init_owned", storage.init_db is database_schema.init_db),
            ("campaign_owned", storage.create_campaign is campaigns.create_campaign),
            ("restore_owned", storage.restore_database is database_lifecycle.restore_database),
            ("storage_facade_budget", by_path["app/core/storage.py"]["lines"] <= 160),
            ("schema_budget", by_path["app/core/database_schema.py"]["lines"] <= 750),
            ("campaign_budget", by_path["app/repositories/campaigns.py"]["lines"] <= 240),
            ("lifecycle_budget", by_path["app/services/database_lifecycle.py"]["lines"] <= 540),
            ("architecture_pass", report["status"] == "PASS" and not report["cycles"]),
        ]
    payload = {
        "title": "VulnFlow 72.0.87 storage orchestration modularization verification",
        "checks": [{"name": name, "passed": passed} for name, passed in checks],
        "result": f"{sum(p for _, p in checks)}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "storage_modularization_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], ""] + [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks]
    lines += ["", f"result: {payload['result']}"]
    (reports / "storage_modularization_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(passed for _, passed in checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
