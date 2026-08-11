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
from app.services.proof_transparency import (
    export_integrity_proof_transparency_entries,
    export_integrity_proof_transparency_heads,
    publish_integrity_proof_transparency_head,
    verify_integrity_proof_transparency_log,
)
from app.services.proof_witness import create_integrity_proof_checkpoint_witness, export_integrity_proof_checkpoint_witnesses

REPORTS = ROOT / "reports"


def _private_key() -> str:
    key = Ed25519PrivateKey.generate()
    return b64encode_raw(key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ))


def main() -> None:
    private = {name: _private_key() for name in ("recovery", "proof", "witness-a", "witness-b", "log")}
    public = {name: public_key_from_private(value) for name, value in private.items()}
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow_v51_transparency_") as temp_name:
        temp = Path(temp_name)
        db, exports = temp / "vulnflow.db", temp / "exports"
        init_db(db)
        add_audit_event(db, finding_id=None, event_type="v51-transparency-smoke", summary="append-only log", actor="smoke")
        checkpoint = create_integrity_proof_revocation_checkpoint(
            db, recovery_key_id="recovery", private_keys=private, public_keys=public, actor="admin"
        )
        for witness_id in ("witness-a", "witness-b"):
            create_integrity_proof_checkpoint_witness(
                db, witness_key_id=witness_id, private_keys=private, public_keys=public, actor="witness-admin"
            )
        published = publish_integrity_proof_transparency_head(
            db, log_key_id="log", private_keys=private, public_keys=public,
            actor="log-admin", minimum_witness_quorum=2,
        )
        entries = export_integrity_proof_transparency_entries(db)
        heads = export_integrity_proof_transparency_heads(db)
        witnesses = export_integrity_proof_checkpoint_witnesses(db)
        log_result = verify_integrity_proof_transparency_log(
            entries, heads, pinned_public_keys={"log": public["log"]},
            checkpoints=[checkpoint], witnesses=witnesses,
            minimum_tree_size=1, trusted_head_sha256=published["head"]["document_sha256"],
        )
        artifact = create_integrity_proof_bundle(
            db, exports, actor="admin", app_version=CURRENT_APP_VERSION, schema_version=CURRENT_SCHEMA_VERSION,
            signing_key="v51-audit-signing-secret-0123456789", signing_key_id="audit-v51",
            signing_keys={"audit-v51": "v51-audit-signing-secret-0123456789"},
            ed25519_private_key=private["proof"], ed25519_public_key=public["proof"], ed25519_key_id="proof",
            require_public_signature=True, minimum_witness_quorum=2, require_transparency_log=True,
        )
        bundle = exports / artifact["stored_filename"]
        result = verify_integrity_proof_bundle(
            bundle,
            ed25519_public_keys={"proof": public["proof"], "recovery": public["recovery"]},
            witness_public_keys={"witness-a": public["witness-a"], "witness-b": public["witness-b"]},
            transparency_public_keys={"log": public["log"]},
            minimum_transparency_tree_size=1,
            trusted_transparency_head_sha256=published["head"]["document_sha256"],
        )
        checks.extend([
            {"name": "schema_42", "passed": CURRENT_SCHEMA_VERSION == 46 and validate_database_file(db)["schema_version"] == 46},
            {"name": "app_72_0_4", "passed": CURRENT_APP_VERSION == "72.0.76"},
            {"name": "entry_chain", "passed": len(entries) == 1 and entries[0]["statement"]["sequence"] == 1},
            {"name": "signed_head", "passed": len(heads) == 1 and heads[0]["statement"]["tree_size"] == 1},
            {"name": "head_pin", "passed": log_result["trusted_head_observed"] is True},
            {"name": "external_log_key", "passed": log_result["log_key_id"] == "log"},
            {"name": "proof_v7", "passed": result["proof_format"] == "vulnflow-integrity-proof/7"},
            {"name": "transparency_verified", "passed": result["transparency_log"]["status"] == "transparency-log-verified"},
            {"name": "witness_quorum", "passed": result["witness_quorum"]["quorum"] == 2},
            {"name": "bundle_valid", "passed": result["valid"] is True},
        ])
        try:
            verify_integrity_proof_bundle(
                bundle,
                ed25519_public_keys={"proof": public["proof"], "recovery": public["recovery"]},
                witness_public_keys={"witness-a": public["witness-a"], "witness-b": public["witness-b"]},
            )
        except ValueError as exc:
            checks.append({"name": "unpinned_log_rejected", "passed": "고정한 log 공개키" in str(exc)})
        else:
            checks.append({"name": "unpinned_log_rejected", "passed": False})

    passed = sum(bool(item["passed"]) for item in checks)
    payload = {
        "title": "VulnFlow 72.0.76 append-only transparency log verification",
        "version": CURRENT_APP_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "transparency_log_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {CURRENT_APP_VERSION}", f"schema: {CURRENT_SCHEMA_VERSION}",
             f"result: {passed}/{len(checks)}", ""]
    lines.extend(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}" for item in checks)
    (REPORTS / "transparency_log_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if passed != len(checks):
        raise SystemExit(f"transparency log verification failed: {passed}/{len(checks)}")
    print(f"transparency log verification passed: {passed}/{len(checks)}")


if __name__ == "__main__":
    main()
