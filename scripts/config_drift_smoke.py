from __future__ import annotations

import json
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import init_db, validate_database_file
from app.services.accounts import create_user
from app.services.config_drift import create_baseline, evaluate_drift, list_baselines, record_drift_check
from app.services.recovery import build_config_audit



def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_config_drift_") as temp:
        db = Path(temp) / "vulnflow.db"
        init_db(db)
        create_user(
            db,
            username="admin",
            password="Baseline-Admin-2026!",
            role="admin",
            actor="config-drift-smoke",
        )
        approved_env = {
            "VULNFLOW_API_TOKENS_JSON": '{"ci":{"token":"token-secret","role":"operator","projects":"*"}}',
            "VULNFLOW_WEBHOOKS_JSON": '{"ops":{"url":"https://user:pass@example.test/private","secret":"hook-secret","events":["workflow.changed"]}}',
            "VULNFLOW_COOKIE_SECURE": "1",
            "VULNFLOW_BACKUP_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_AUDIT_REQUIRE_SIGNATURE": "1",
            "VULNFLOW_SIGNING_KEYS_JSON": '{"audit-v1":"0123456789abcdef","backup-v1":"fedcba9876543210"}',
            "VULNFLOW_AUDIT_ACTIVE_KEY_ID": "audit-v1",
            "VULNFLOW_BACKUP_ACTIVE_KEY_ID": "backup-v1",
            "VULNFLOW_CURSOR_SIGNING_KEY": "cursor-key-0123456789",
        }
        approved = build_config_audit(env=approved_env, db_path=db, base_dir=ROOT)
        baseline = create_baseline(db, approved, actor="admin", note="smoke approved baseline")
        baseline_text = json.dumps(baseline["snapshot"], ensure_ascii=False, sort_keys=True)
        leaked = [
            value for value in ("Baseline-Admin-2026!", "token-secret", "hook-secret", "user:pass", "/private")
            if value in baseline_text
        ]
        if leaked:
            raise SystemExit("redacted baseline contains secret material: " + ", ".join(leaked))
        in_sync = evaluate_drift(db, build_config_audit(env=approved_env, db_path=db, base_dir=ROOT))
        if in_sync["status"] != "IN_SYNC":
            raise SystemExit("approved configuration did not remain in sync")

        changed_env = dict(approved_env)
        changed_env["VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP"] = "1"
        changed_env["VULNFLOW_EVIDENCE_REQUIRE_CLEAN"] = "0"
        changed = build_config_audit(env=changed_env, db_path=db, base_dir=ROOT)
        drift = evaluate_drift(db, changed)
        if drift["status"] != "DRIFT" or drift["severity"] != "HIGH" or drift["change_count"] < 2:
            raise SystemExit("high-risk configuration drift was not detected")
        check = record_drift_check(db, changed, actor="auditor")
        if check["status"] != "DRIFT":
            raise SystemExit("drift check was not recorded")
        create_baseline(db, changed, actor="admin", note="approved controlled change")
        if evaluate_drift(db, changed)["status"] != "IN_SYNC":
            raise SystemExit("re-baselined configuration is not in sync")
        validation = validate_database_file(db)
        if validation["schema_version"] != 42:
            raise SystemExit("schema 43 restore validation failed")

        result = {
            "baseline_id": baseline["baseline_id"],
            "redaction_passed": True,
            "initial_status": in_sync["status"],
            "drift_status": drift["status"],
            "drift_severity": drift["severity"],
            "change_count": drift["change_count"],
            "recorded_check_id": check["check_id"],
            "rebaseline_status": evaluate_drift(db, changed)["status"],
            "baseline_history_count": len(list_baselines(db)),
            "schema_version": validation["schema_version"],
        }
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "config_drift_verification.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        (reports / "config_drift_verification.txt").write_text(
            "VulnFlow 72.0.86 configuration baseline and drift verification\n"
            "redacted baseline: passed\n"
            f"initial status: {result['initial_status']}\n"
            f"high-risk drift: {result['drift_status']} / {result['drift_severity']} / {result['change_count']} changes\n"
            f"rebaseline status: {result['rebaseline_status']}\n"
            f"schema: {result['schema_version']}\n",
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
