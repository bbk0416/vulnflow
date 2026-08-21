from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import init_db, validate_database_file
from app.services.config_changes import (
    create_change_request,
    decide_change_request,
    evaluate_change_control,
    promote_change_request,
)
from app.services.config_drift import create_baseline, evaluate_drift
from app.services.recovery import build_config_audit


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_config_change_") as temp:
        db = Path(temp) / "vulnflow.db"
        init_db(db)
        base_env = {
            "VULNFLOW_COOKIE_SECURE": "0",
            "VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP": "0",
            "VULNFLOW_EVIDENCE_REQUIRE_CLEAN": "1",
        }
        base = build_config_audit(env=base_env, db_path=db, base_dir=ROOT)
        create_baseline(db, base, actor="bootstrap-admin", note="initial approved state")
        target_env = dict(base_env)
        target_env["VULNFLOW_COOKIE_SECURE"] = "1"
        target = build_config_audit(env=target_env, db_path=db, base_dir=ROOT)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        request = create_change_request(
            db, target, actor="operator-a", title="Enable Secure cookie",
            reason="TLS termination rollout completed",
            rollback_plan="restore VULNFLOW_COOKIE_SECURE=0 and restart the instance",
            window_start=(now - timedelta(minutes=5)).isoformat(),
            window_end=(now + timedelta(hours=2)).isoformat(),
        )
        self_approval_blocked = False
        try:
            decide_change_request(db, request["request_id"], actor="operator-a", decision="APPROVE")
        except ValueError:
            self_approval_blocked = True
        if not self_approval_blocked:
            raise SystemExit("requester self-approval was not blocked")
        decide_change_request(db, request["request_id"], actor="approver-b", decision="APPROVE")
        controlled = evaluate_change_control(db, target, evaluate_drift(db, target))
        if controlled["control_status"] != "APPROVED_WINDOW":
            raise SystemExit("approved target was not recognized during the change window")
        unexpected_env = dict(target_env)
        unexpected_env["VULNFLOW_EVIDENCE_REQUIRE_CLEAN"] = "0"
        unexpected = build_config_audit(env=unexpected_env, db_path=db, base_dir=ROOT)
        unexpected_result = evaluate_change_control(db, unexpected, evaluate_drift(db, unexpected))
        if unexpected_result["control_status"] != "UNAPPROVED":
            raise SystemExit("additional unapproved drift was incorrectly accepted")
        applied = promote_change_request(
            db, request["request_id"], target, actor="approver-b", note="validated during window"
        )
        if applied["status"] != "APPLIED" or evaluate_drift(db, target)["status"] != "IN_SYNC":
            raise SystemExit("approved target was not promoted to the active baseline")
        validation = validate_database_file(db)
        if validation["schema_version"] != 42:
            raise SystemExit("schema 43 restore validation failed")
        result = {
            "request_id": request["request_id"],
            "self_approval_blocked": self_approval_blocked,
            "approved_window_status": controlled["control_status"],
            "unexpected_drift_status": unexpected_result["control_status"],
            "final_status": applied["status"],
            "baseline_status": evaluate_drift(db, target)["status"],
            "schema_version": validation["schema_version"],
        }
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "config_change_control_verification.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        (reports / "config_change_control_verification.txt").write_text(
            "VulnFlow 72.0.99 configuration change control verification\n"
            f"self approval blocked: {result['self_approval_blocked']}\n"
            f"approved window: {result['approved_window_status']}\n"
            f"additional drift: {result['unexpected_drift_status']}\n"
            f"final request: {result['final_status']}\n"
            f"active baseline: {result['baseline_status']}\n"
            f"schema: {result['schema_version']}\n",
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
