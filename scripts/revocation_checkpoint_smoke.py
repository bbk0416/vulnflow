from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.public_signing import b64encode_raw, public_key_from_private
from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, add_audit_event, init_db, validate_database_file
from app.services.integrity_proofs import create_integrity_proof_bundle, verify_integrity_proof_bundle
from app.services.proof_checkpoint import (
    checkpoint_document_sha256,
    create_integrity_proof_revocation_checkpoint,
    export_integrity_proof_revocation_checkpoints,
    verify_revocation_checkpoint_chain,
)
from app.services.proof_revocation import create_integrity_proof_key_revocation, export_integrity_proof_key_revocations
from app.services.proof_trust import export_integrity_proof_key_transitions

HMAC_ID = "audit-checkpoint-smoke"
HMAC_KEY = "audit-checkpoint-smoke-secret-0123456789"


def _private() -> str:
    key = Ed25519PrivateKey.generate()
    return b64encode_raw(key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ))


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow_revocation_checkpoint_") as temp_name:
        root = Path(temp_name)
        db, exports = root / "vulnflow.db", root / "exports"
        init_db(db)
        checks["schema_42"] = validate_database_file(db)["schema_version"] == CURRENT_SCHEMA_VERSION == 46
        private = {name: _private() for name in ("compromised", "replacement", "recovery")}
        public = {name: public_key_from_private(value) for name, value in private.items()}

        first = create_integrity_proof_revocation_checkpoint(
            db, recovery_key_id="recovery", private_keys=private, public_keys=public,
            actor="incident-admin",
        )
        checks["first_checkpoint"] = first["statement"]["sequence"] == 1
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat()
        create_integrity_proof_key_revocation(
            db, revoked_key_id="compromised", replacement_key_id="replacement", recovery_key_id="recovery",
            private_keys=private, public_keys=public, actor="incident-admin",
            reason="confirmed checkpoint smoke compromise", invalid_after=cutoff,
        )
        second = create_integrity_proof_revocation_checkpoint(
            db, recovery_key_id="recovery", private_keys=private, public_keys=public,
            actor="incident-admin",
        )
        checks["monotonic_sequence"] = second["statement"]["sequence"] == 2
        checks["previous_digest_link"] = second["statement"]["previous_checkpoint_sha256"] == checkpoint_document_sha256(first)
        checkpoints = export_integrity_proof_revocation_checkpoints(db)
        state = verify_revocation_checkpoint_chain(
            checkpoints, pinned_public_keys={"recovery": public["recovery"]},
            revocations=export_integrity_proof_key_revocations(db),
            transitions=export_integrity_proof_key_transitions(db), minimum_sequence=2,
        )
        checks["registry_freshness"] = state.get("status") == "revocation-freshness-verified"

        add_audit_event(db, finding_id=None, event_type="checkpoint.smoke", summary="checkpoint proof", actor="smoke")
        artifact = create_integrity_proof_bundle(
            db, exports, actor="smoke", app_version=CURRENT_APP_VERSION,
            schema_version=CURRENT_SCHEMA_VERSION, signing_key=HMAC_KEY,
            signing_key_id=HMAC_ID, signing_keys={HMAC_ID: HMAC_KEY},
            ed25519_private_key=private["replacement"], ed25519_public_key=public["replacement"],
            ed25519_key_id="replacement", require_public_signature=True,
        )
        bundle = exports / artifact["stored_filename"]
        latest_digest = checkpoint_document_sha256(second)
        checked = verify_integrity_proof_bundle(
            bundle, ed25519_public_keys={"recovery": public["recovery"]},
            minimum_checkpoint_sequence=2, trusted_checkpoint_sha256=latest_digest,
        )
        checks["proof_v5"] = checked.get("proof_format") == "vulnflow-integrity-proof/5"
        checks["freshness_result"] = checked.get("revocation_freshness", {}).get("sequence") == 2
        try:
            verify_integrity_proof_bundle(
                bundle, ed25519_public_keys={"recovery": public["recovery"]}, minimum_checkpoint_sequence=3,
            )
            checks["minimum_sequence_enforced"] = False
        except ValueError:
            checks["minimum_sequence_enforced"] = True

        cli = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "verify_integrity_proof.py"), str(bundle),
            "--public-key", f"recovery={public['recovery']}",
            "--minimum-checkpoint", "2", "--trusted-checkpoint-sha256", latest_digest,
        ], capture_output=True, text=True)
        checks["offline_checkpoint_verification"] = cli.returncode == 0

        serialized = json.dumps(checkpoints, ensure_ascii=False)
        checks["private_material_redacted"] = all(value not in serialized for value in private.values())
        with sqlite3.connect(db) as conn:
            try:
                conn.execute("DELETE FROM integrity_proof_revocation_checkpoints")
                checks["immutable_checkpoints"] = False
            except sqlite3.DatabaseError:
                checks["immutable_checkpoints"] = True

    passed, total = sum(checks.values()), len(checks)
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    payload = {"version": CURRENT_APP_VERSION, "schema_version": CURRENT_SCHEMA_VERSION,
               "checks": checks, "passed": passed, "total": total}
    (reports / "revocation_checkpoint_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = ["VulnFlow revocation registry checkpoint verification",
             f"version: {CURRENT_APP_VERSION}", f"schema_version: {CURRENT_SCHEMA_VERSION}",
             f"result: {passed}/{total}"] + [f"- {name}: {'PASS' if ok else 'FAIL'}" for name, ok in checks.items()]
    (reports / "revocation_checkpoint_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
