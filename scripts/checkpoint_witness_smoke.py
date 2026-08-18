from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.public_signing import b64encode_raw, public_key_from_private
from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, add_audit_event, init_db
from app.services.integrity_proofs import create_integrity_proof_bundle, verify_integrity_proof_bundle
from app.services.proof_checkpoint import create_integrity_proof_revocation_checkpoint
from app.services.proof_witness import create_integrity_proof_checkpoint_witness

REPORTS = ROOT / "reports"


def _private_key() -> str:
    key = Ed25519PrivateKey.generate()
    return b64encode_raw(key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ))


def main() -> None:
    private = {name: _private_key() for name in ("recovery", "proof", "witness-a", "witness-b")}
    public = {name: public_key_from_private(value) for name, value in private.items()}
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow_v50_witness_") as temp_name:
        temp = Path(temp_name)
        db, exports = temp / "vulnflow.db", temp / "exports"
        init_db(db)
        add_audit_event(db, finding_id=None, event_type="v50-witness-smoke", summary="witness quorum", actor="smoke")
        checkpoint = create_integrity_proof_revocation_checkpoint(
            db, recovery_key_id="recovery", private_keys=private, public_keys=public, actor="admin"
        )
        for witness_id in ("witness-a", "witness-b"):
            create_integrity_proof_checkpoint_witness(
                db, witness_key_id=witness_id, private_keys=private, public_keys=public, actor="witness-admin"
            )
        artifact = create_integrity_proof_bundle(
            db, exports, actor="admin", app_version=CURRENT_APP_VERSION, schema_version=CURRENT_SCHEMA_VERSION,
            signing_key="v50-audit-signing-secret-0123456789", signing_key_id="audit-v50",
            signing_keys={"audit-v50": "v50-audit-signing-secret-0123456789"},
            ed25519_private_key=private["proof"], ed25519_public_key=public["proof"], ed25519_key_id="proof",
            require_public_signature=True, minimum_witness_quorum=2,
        )
        bundle = exports / artifact["stored_filename"]
        result = verify_integrity_proof_bundle(
            bundle,
            ed25519_public_keys={"proof": public["proof"], "recovery": public["recovery"]},
            witness_public_keys={"witness-a": public["witness-a"], "witness-b": public["witness-b"]},
        )
        checks.extend([
            {"name": "schema_42", "passed": CURRENT_SCHEMA_VERSION == 46},
            {"name": "proof_v6", "passed": result["proof_format"] == "vulnflow-integrity-proof/6"},
            {"name": "checkpoint_sequence", "passed": checkpoint["statement"]["sequence"] == 1},
            {"name": "quorum_verified", "passed": result["witness_quorum"]["status"] == "witness-quorum-verified"},
            {"name": "quorum_two", "passed": result["witness_quorum"]["quorum"] == 2},
            {"name": "distinct_witnesses", "passed": result["witness_quorum"]["witness_key_ids"] == ["witness-a", "witness-b"]},
            {"name": "freshness_verified", "passed": result["revocation_freshness"]["status"] == "revocation-freshness-verified"},
            {"name": "bundle_valid", "passed": result["valid"] is True},
        ])
        try:
            verify_integrity_proof_bundle(
                bundle,
                ed25519_public_keys={"proof": public["proof"], "recovery": public["recovery"]},
                witness_public_keys={"witness-a": public["witness-a"]},
            )
        except ValueError as exc:
            checks.append({"name": "insufficient_quorum_rejected", "passed": "quorum" in str(exc)})
        else:
            checks.append({"name": "insufficient_quorum_rejected", "passed": False})
        try:
            create_integrity_proof_checkpoint_witness(
                db, witness_key_id="recovery", private_keys=private, public_keys=public, actor="admin"
            )
        except ValueError as exc:
            checks.append({"name": "recovery_not_witness", "passed": "독립" in str(exc)})
        else:
            checks.append({"name": "recovery_not_witness", "passed": False})
        try:
            create_integrity_proof_checkpoint_witness(
                db, witness_key_id="witness-a", private_keys=private, public_keys=public, actor="admin"
            )
        except ValueError as exc:
            checks.append({"name": "duplicate_witness_rejected", "passed": "이미 checkpoint" in str(exc)})
        else:
            checks.append({"name": "duplicate_witness_rejected", "passed": False})

    passed = sum(bool(item["passed"]) for item in checks)
    payload = {"title": "VulnFlow 72.0.91 checkpoint witness quorum verification", "version": CURRENT_APP_VERSION,
               "schema_version": CURRENT_SCHEMA_VERSION, "passed": passed, "total": len(checks), "checks": checks}
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "checkpoint_witness_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {CURRENT_APP_VERSION}", f"schema: {CURRENT_SCHEMA_VERSION}",
             f"result: {passed}/{len(checks)}", ""]
    lines.extend(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}" for item in checks)
    (REPORTS / "checkpoint_witness_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if passed != len(checks):
        raise SystemExit(f"checkpoint witness verification failed: {passed}/{len(checks)}")
    print(f"checkpoint witness verification passed: {passed}/{len(checks)}")


if __name__ == "__main__":
    main()
