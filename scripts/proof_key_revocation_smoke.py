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
from app.services.proof_revocation import create_integrity_proof_key_revocation, export_integrity_proof_key_revocations
from app.services.proof_trust import create_integrity_proof_key_transition

HMAC_ID = "audit-revocation-smoke"
HMAC_KEY = "audit-revocation-smoke-secret-0123456789"


def _private() -> str:
    key = Ed25519PrivateKey.generate()
    return b64encode_raw(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def _proof(db: Path, exports: Path, key_id: str, private: str, public: str) -> Path:
    add_audit_event(db, finding_id=None, event_type="revocation.smoke", summary="revocation smoke", actor="smoke")
    artifact = create_integrity_proof_bundle(
        db, exports, actor="smoke", app_version=CURRENT_APP_VERSION,
        schema_version=CURRENT_SCHEMA_VERSION, signing_key=HMAC_KEY,
        signing_key_id=HMAC_ID, signing_keys={HMAC_ID: HMAC_KEY},
        ed25519_private_key=private, ed25519_public_key=public,
        ed25519_key_id=key_id, require_public_signature=True,
    )
    return exports / artifact["stored_filename"]


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow_proof_revocation_") as temp_name:
        root = Path(temp_name)
        db, exports = root / "vulnflow.db", root / "exports"
        init_db(db)
        checks["schema_40"] = validate_database_file(db)["schema_version"] == CURRENT_SCHEMA_VERSION == 40
        private = {name: _private() for name in ("compromised", "replacement", "recovery", "attacker")}
        public = {name: public_key_from_private(value) for name, value in private.items()}

        old_bundle = _proof(db, exports, "compromised", private["compromised"], public["compromised"])
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat()
        revocation = create_integrity_proof_key_revocation(
            db, revoked_key_id="compromised", replacement_key_id="replacement", recovery_key_id="recovery",
            private_keys=private, public_keys=public, actor="incident-admin",
            reason="confirmed emergency signing-key compromise", invalid_after=cutoff,
        )
        rows = export_integrity_proof_key_revocations(db)
        checks["revocation_created"] = len(rows) == 1
        serialized = json.dumps(rows, ensure_ascii=False)
        checks["private_material_redacted"] = all(value not in serialized for value in private.values())
        checks["raw_reason_redacted"] = "confirmed emergency signing-key compromise" not in serialized

        try:
            verify_integrity_proof_bundle(
                old_bundle,
                ed25519_public_keys={"compromised": public["compromised"], "recovery": public["recovery"]},
                external_key_revocations=rows,
            )
            checks["old_proof_blocked"] = False
        except ValueError:
            checks["old_proof_blocked"] = True

        replacement_bundle = _proof(db, exports, "replacement", private["replacement"], public["replacement"])
        checked = verify_integrity_proof_bundle(replacement_bundle, ed25519_public_keys={"recovery": public["recovery"]})
        checks["proof_v4"] = checked.get("proof_format") == "vulnflow-integrity-proof/4"
        checks["recovered_public_key"] = checked.get("trust_status") == "recovered-public-key"
        checks["revocation_path"] = checked.get("revocation_ids") == [revocation["statement"]["revocation_id"]]

        try:
            verify_integrity_proof_bundle(replacement_bundle, ed25519_public_keys={"compromised": public["compromised"]})
            checks["recovery_pin_required"] = False
        except ValueError:
            checks["recovery_pin_required"] = True

        create_integrity_proof_key_transition(
            db, from_key_id="compromised", to_key_id="attacker",
            private_keys=private, public_keys=public, actor="attacker",
            reason="post-incident malicious transition",
        )
        attacker_bundle = _proof(db, exports, "attacker", private["attacker"], public["attacker"])
        try:
            verify_integrity_proof_bundle(
                attacker_bundle,
                ed25519_public_keys={"compromised": public["compromised"], "recovery": public["recovery"]},
            )
            checks["post_incident_transition_blocked"] = False
        except ValueError:
            checks["post_incident_transition_blocked"] = True

        revocations_file = root / "revocations.json"
        revocations_file.write_text(json.dumps(rows), encoding="utf-8")
        cli = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "verify_integrity_proof.py"), str(old_bundle),
            "--public-key", f"compromised={public['compromised']}",
            "--public-key", f"recovery={public['recovery']}",
            "--revocations", str(revocations_file),
        ], capture_output=True, text=True)
        checks["offline_external_revocation"] = cli.returncode != 0

        with sqlite3.connect(db) as conn:
            try:
                conn.execute("DELETE FROM integrity_proof_key_revocations")
                checks["immutable_revocation"] = False
            except sqlite3.DatabaseError:
                checks["immutable_revocation"] = True

    passed, total = sum(checks.values()), len(checks)
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    payload = {"version": CURRENT_APP_VERSION, "schema_version": CURRENT_SCHEMA_VERSION,
               "checks": checks, "passed": passed, "total": total}
    (reports / "proof_key_revocation_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = ["VulnFlow emergency proof-key revocation verification",
             f"version: {CURRENT_APP_VERSION}", f"schema_version: {CURRENT_SCHEMA_VERSION}",
             f"result: {passed}/{total}"] + [f"- {name}: {'PASS' if ok else 'FAIL'}" for name, ok in checks.items()]
    (reports / "proof_key_revocation_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
