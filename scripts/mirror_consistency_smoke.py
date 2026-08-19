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
from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, add_audit_event, init_db, validate_database_file
from app.services.integrity_proofs import create_integrity_proof_bundle, verify_integrity_proof_bundle
from app.services.proof_checkpoint import create_integrity_proof_revocation_checkpoint
from app.services.proof_consistency import (
    create_integrity_proof_mirror_consistency_checkpoint,
    export_integrity_proof_mirror_consistency_checkpoints,
    verify_mirror_consistency_chain,
)
from app.services.proof_mirror import create_integrity_proof_transparency_mirror_receipt, export_integrity_proof_transparency_mirror_receipts
from app.services.proof_transparency import export_integrity_proof_transparency_heads, publish_integrity_proof_transparency_head
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
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow-v53-consistency-") as temp_name:
        temp = Path(temp_name)
        db, exports = temp / "vulnflow.db", temp / "exports"
        init_db(db)
        names = ("recovery", "proof", "witness-a", "witness-b", "log", "mirror-a", "mirror-b")
        private = {name: _private_key() for name in names}
        public = {name: public_key_from_private(value) for name, value in private.items()}
        add_audit_event(db, finding_id=None, event_type="v53-consistency-smoke", summary="consistency", actor="smoke")
        create_integrity_proof_revocation_checkpoint(db, recovery_key_id="recovery", private_keys=private, public_keys=public, actor="admin")
        for key_id in ("witness-a", "witness-b"):
            create_integrity_proof_checkpoint_witness(db, witness_key_id=key_id, private_keys=private, public_keys=public, actor="admin")
        head = publish_integrity_proof_transparency_head(db, log_key_id="log", private_keys=private, public_keys=public, actor="admin", minimum_witness_quorum=2)
        for key_id in ("mirror-a", "mirror-b"):
            create_integrity_proof_transparency_mirror_receipt(db, mirror_key_id=key_id, private_keys=private, public_keys=public, actor="admin")
        checkpoint = create_integrity_proof_mirror_consistency_checkpoint(
            db, mirror_key_ids=["mirror-a", "mirror-b"], minimum_quorum=2,
            private_keys=private, public_keys=public, actor="admin",
        )
        documents = export_integrity_proof_mirror_consistency_checkpoints(db)
        receipts = export_integrity_proof_transparency_mirror_receipts(db)
        heads = export_integrity_proof_transparency_heads(db)
        verified = verify_mirror_consistency_chain(
            documents, heads=heads, receipts=receipts,
            pinned_public_keys={"mirror-a": public["mirror-a"], "mirror-b": public["mirror-b"]},
            minimum_quorum=2, trusted_checkpoint_sha256=checkpoint["document_sha256"],
        )
        artifact = create_integrity_proof_bundle(
            db, exports, actor="admin", app_version=CURRENT_APP_VERSION, schema_version=CURRENT_SCHEMA_VERSION,
            signing_key="v53-audit-signing-secret-0123456789", signing_key_id="audit-v53",
            signing_keys={"audit-v53": "v53-audit-signing-secret-0123456789"},
            ed25519_private_key=private["proof"], ed25519_public_key=public["proof"], ed25519_key_id="proof",
            require_public_signature=True, minimum_witness_quorum=2, require_transparency_log=True,
            minimum_mirror_quorum=2, require_mirror_gossip=True, require_mirror_consistency=True,
        )
        result = verify_integrity_proof_bundle(
            exports / artifact["stored_filename"],
            ed25519_public_keys={"proof": public["proof"], "recovery": public["recovery"]},
            witness_public_keys={"witness-a": public["witness-a"], "witness-b": public["witness-b"]},
            transparency_public_keys={"log": public["log"]},
            mirror_public_keys={"mirror-a": public["mirror-a"], "mirror-b": public["mirror-b"]},
            minimum_mirror_quorum=2, minimum_mirror_consistency_quorum=2,
            trusted_transparency_head_sha256=head["head"]["document_sha256"],
            trusted_mirror_consistency_checkpoint_sha256=checkpoint["document_sha256"],
        )
        checks.extend([
            {"name": "schema_42", "passed": validate_database_file(db)["schema_version"] == 46},
            {"name": "app_72_0_4", "passed": CURRENT_APP_VERSION == "72.0.92"},
            {"name": "checkpoint_count", "passed": len(documents) == 1},
            {"name": "two_mirror_signatures", "passed": len(documents[0]["signatures"]) == 2},
            {"name": "consistency_quorum", "passed": verified["quorum"] == 2},
            {"name": "trusted_checkpoint", "passed": verified["trusted_checkpoint_observed"] is True},
            {"name": "proof_v9", "passed": result["proof_format"] == "vulnflow-integrity-proof/9"},
            {"name": "consistency_verified", "passed": result["mirror_consistency"]["status"] == "mirror-consistency-verified"},
            {"name": "mirror_gossip_verified", "passed": result["mirror_gossip"]["status"] == "mirror-gossip-verified"},
            {"name": "transparency_verified", "passed": result["transparency_log"]["status"] == "transparency-log-verified"},
            {"name": "bundle_valid", "passed": result["valid"] is True},
        ])
    passed = sum(bool(item["passed"]) for item in checks)
    payload = {"title": "VulnFlow 72.0.92 mirror consistency verification", "version": CURRENT_APP_VERSION,
               "schema_version": CURRENT_SCHEMA_VERSION, "passed": passed, "total": len(checks), "checks": checks}
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "mirror_consistency_verification.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    lines = [payload["title"], f"version: {CURRENT_APP_VERSION}", f"schema: {CURRENT_SCHEMA_VERSION}", f"result: {passed}/{len(checks)}", ""]
    lines.extend(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}" for item in checks)
    (REPORTS / "mirror_consistency_verification.txt").write_text("\n".join(lines) + "\n")
    if passed != len(checks):
        raise SystemExit(f"mirror consistency verification failed: {passed}/{len(checks)}")
    print(f"mirror consistency verification passed: {passed}/{len(checks)}")


if __name__ == "__main__":
    main()
