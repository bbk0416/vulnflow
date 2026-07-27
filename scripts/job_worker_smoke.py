from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WORKER_CODE = r'''
import os
import sys
from pathlib import Path
root=Path(os.environ["VULNFLOW_ROOT"])
sys.path.insert(0,str(root))
from app import main
from app.core.storage import claim_background_job, complete_background_job, fail_background_job
worker_id=os.environ["VULNFLOW_WORKER_ID"]
while True:
    job=claim_background_job(main.DB_PATH,worker_id=worker_id,lease_seconds=30)
    if not job:
        break
    try:
        result=main._execute_background_job(job,worker_id=worker_id)
        complete_background_job(main.DB_PATH,job_id=job["job_id"],worker_id=worker_id,result=result)
    except Exception as exc:
        fail_background_job(main.DB_PATH,job_id=job["job_id"],worker_id=worker_id,error=str(exc))
'''


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_job_workers_") as temp_dir:
        db = Path(temp_dir) / "jobs.sqlite3"
        os.environ["VULNFLOW_DB"] = str(db)
        os.environ["VULNFLOW_JOB_WORKER_ENABLED"] = "0"
        from app import main as app_main
        from app.core.storage import create_background_job, init_db, list_background_jobs

        init_db(db)
        app_main._ensure_policy_registry()
        if app_main.count_findings(db) == 0:
            app_main.upsert_findings(db, app_main._load_sample_rows(app_main.SAMPLE_PATH), actor="job-smoke")
            app_main.rescore_all(audit=False, actor="job-smoke")
        for index in range(12):
            create_background_job(
                db,
                job_type="RESCORE_ALL",
                requested_by="job-smoke",
                dedupe_key=f"job-smoke:{index}",
            )

        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["VULNFLOW_ROOT"] = str(ROOT)
        processes = []
        for worker_id in ("process-a", "process-b"):
            worker_env = env.copy()
            worker_env["VULNFLOW_WORKER_ID"] = worker_id
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-c", WORKER_CODE],
                    cwd=ROOT,
                    env=worker_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            if process.returncode != 0:
                raise SystemExit(f"worker failed: {process.returncode}\n{stdout}\n{stderr}")

        jobs = list_background_jobs(db, limit=100)
        if len(jobs) != 12:
            raise SystemExit(f"expected 12 jobs, got {len(jobs)}")
        if any(job["status"] != "SUCCEEDED" for job in jobs):
            raise SystemExit("not all jobs succeeded")
        if any(int(job["attempts"]) != 1 for job in jobs):
            raise SystemExit("a job was claimed more than once")
        owners = {str(job.get("lease_owner") or "") for job in jobs}
        # lease_owner is cleared on completion; audit/test assertions prove exclusive attempts.
        print("jobs succeeded: 12/12")
        print("duplicate claims: 0")
        print("multi-process job smoke passed: 2 workers")


if __name__ == "__main__":
    main()
