from __future__ import annotations

import ast
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import init_db
from app.repositories import job_execution, job_records, jobs


def main() -> int:
    root = ROOT
    checks: dict[str, bool] = {}
    checks["facade_create_identity"] = jobs.create_background_job is job_records.create_background_job
    checks["facade_claim_identity"] = jobs.claim_background_job is job_execution.claim_background_job
    checks["facade_complete_identity"] = jobs.complete_background_job is job_execution.complete_background_job
    checks["records_no_execution_import"] = "app.repositories.job_execution" not in (root / "app/repositories/job_records.py").read_text(encoding="utf-8")
    checks["execution_uses_records"] = "app.repositories.job_records" in (root / "app/repositories/job_execution.py").read_text(encoding="utf-8")

    importers: list[str] = []
    for path in sorted((root / "app").rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if relative == "app/repositories/jobs.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.repositories.jobs":
                importers.append(relative)
            elif isinstance(node, ast.Import) and any(alias.name == "app.repositories.jobs" for alias in node.names):
                importers.append(relative)
    checks["internal_facade_importers_zero"] = not importers

    with tempfile.TemporaryDirectory(prefix="vulnflow-job-boundary-") as tmp:
        db = Path(tmp) / "jobs.sqlite3"
        init_db(db)
        created = job_records.create_background_job(db, job_type="RESCORE_ALL", requested_by="smoke")
        claimed = job_execution.claim_background_job(db, worker_id="smoke-worker")
        completed = job_execution.complete_background_job(
            db, job_id=created["job_id"], worker_id="smoke-worker", result={"ok": True}
        )
        checks["direct_create"] = bool(created.get("job_id"))
        checks["direct_claim"] = bool(claimed and claimed.get("status") == "RUNNING")
        checks["direct_complete"] = completed.get("status") == "SUCCEEDED"
        checks["facade_read"] = jobs.get_background_job(db, created["job_id"]) == completed

    report = {
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "internal_facade_importers": importers,
    }
    output = root / "reports" / "job_repository_boundary_verification.txt"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
