from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.services.integrity_proofs as facade
from app.core.architecture import build_architecture_report
from app.core.database_schema import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION
from app.core.storage import add_audit_event, init_db
from app.services.integrity_proof_bundle import create_integrity_proof_bundle
from app.services.integrity_proof_common import PROOF_FORMAT
from app.services.integrity_proof_verifier import verify_integrity_proof_bundle


def main_smoke() -> None:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    with tempfile.TemporaryDirectory(prefix="vulnflow-v70-proof-boundary-") as temp:
        root = Path(temp)
        db = root / "proof.db"
        export_dir = root / "exports"
        key_id = "v70-proof-boundary"
        key = "v70-proof-boundary-signing-key-0123456789"
        init_db(db)
        add_audit_event(
            db,
            finding_id=None,
            event_type="proof-boundary",
            summary="VulnFlow 70 integrity proof boundary smoke",
            actor="v70-smoke",
        )
        artifact = create_integrity_proof_bundle(
            db,
            export_dir,
            actor="v70-smoke",
            app_version=CURRENT_APP_VERSION,
            schema_version=CURRENT_SCHEMA_VERSION,
            signing_key=key,
            signing_key_id=key_id,
            signing_keys={key_id: key},
        )
        result = verify_integrity_proof_bundle(
            export_dir / artifact["stored_filename"],
            signing_keys={key_id: key},
        )

    internal_importers = [
        item["path"]
        for item in architecture["modules"]
        if item["path"] != "app/services/integrity_proofs.py"
        and "app.services.integrity_proofs" in set(item.get("internal_imports") or [])
    ]
    checks = {
        "version_72_0_7": CURRENT_APP_VERSION == "72.0.96",
        "schema_42": CURRENT_SCHEMA_VERSION == 46,
        "proof_v9_registry": PROOF_FORMAT == "vulnflow-integrity-proof/9",
        "architecture_pass": architecture["status"] == "PASS",
        "facade_budget": by_path["app/services/integrity_proofs.py"]["lines"] <= 80,
        "bundle_budget": by_path["app/services/integrity_proof_bundle.py"]["lines"] <= 520,
        "verifier_budget": by_path["app/services/integrity_proof_verifier.py"]["lines"] <= 760,
        "no_internal_facade_imports": internal_importers == [],
        "compatibility_identity": (
            facade.create_integrity_proof_bundle is create_integrity_proof_bundle
            and facade.verify_integrity_proof_bundle is verify_integrity_proof_bundle
        ),
        "hmac_round_trip": result["valid"] is True and result["proof_format"] == "vulnflow-integrity-proof/1",
    }
    payload = {
        "title": "VulnFlow 72.0.96 integrity proof boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "result": f"{sum(checks.values())}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "integrity_proof_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "integrity_proof_boundary_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main_smoke()
