from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, add_audit_event, init_db
from app.services.integrity_proofs import create_integrity_proof_bundle, verify_integrity_proof_bundle

KEY_ID = "proof-smoke-v1"
KEY = "proof-smoke-signing-key-0123456789"


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow_integrity_proof_smoke_") as temp_name:
        temp = Path(temp_name)
        db = temp / "vulnflow.db"
        export_dir = temp / "exports"
        init_db(db)
        add_audit_event(db, finding_id=None, event_type="proof.smoke", summary="portable proof", actor="smoke")
        artifact = create_integrity_proof_bundle(
            db,
            export_dir,
            actor="admin",
            app_version=CURRENT_APP_VERSION,
            schema_version=CURRENT_SCHEMA_VERSION,
            signing_key=KEY,
            signing_key_id=KEY_ID,
            signing_keys={KEY_ID: KEY},
            retention_days=7,
        )
        bundle = export_dir / artifact["stored_filename"]
        checked = verify_integrity_proof_bundle(bundle, signing_keys={KEY_ID: KEY})
        checks["service_verify"] = checked.get("valid") is True
        checks["signed_key_id"] = checked.get("signing_key_id") == KEY_ID
        checks["audit_head"] = int(checked.get("audit", {}).get("last_seq") or 0) >= 1
        checks["artifact_type"] = artifact.get("export_type") == "INTEGRITY_PROOF_ZIP"
        checks["no_secret_in_bundle"] = KEY.encode() not in bundle.read_bytes()
        with zipfile.ZipFile(bundle) as archive:
            checks["portable_files"] = set(archive.namelist()) == {
                "manifest.json",
                "audit-events.jsonl",
                "audit-checkpoints.json",
                "audit-prune-history.json",
                "execution-receipt-archives.json",
                "SHA256SUMS.txt",
                "proof.hmac",
            }
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_integrity_proof.py"), str(bundle), "--key", f"{KEY_ID}={KEY}"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        checks["offline_cli"] = completed.returncode == 0 and json.loads(completed.stdout).get("valid") is True
        wrong = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_integrity_proof.py"), str(bundle), "--key", f"{KEY_ID}=wrong-proof-key-0123456789"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        checks["wrong_key_rejected"] = wrong.returncode != 0

    report = {
        "version": CURRENT_APP_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "checks": checks,
        "passed": sum(1 for value in checks.values() if value),
        "total": len(checks),
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "integrity_proof_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow portable integrity proof verification",
        f"version: {CURRENT_APP_VERSION}",
        f"schema_version: {CURRENT_SCHEMA_VERSION}",
        "",
    ] + [f"{'PASS' if value else 'FAIL'}  {name}" for name, value in checks.items()]
    lines.append("")
    lines.append(f"result: {report['passed']}/{report['total']}")
    (reports / "integrity_proof_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if report["passed"] != report["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
