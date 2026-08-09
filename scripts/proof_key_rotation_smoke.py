from __future__ import annotations

import json
import sqlite3
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
from app.services.proof_trust import create_integrity_proof_key_transition, list_integrity_proof_key_transitions

HMAC_KEY_ID = "audit-rotation-smoke"
HMAC_KEY = "audit-rotation-smoke-secret-0123456789"


def _private_key() -> str:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64encode_raw(raw)


def _proof(db: Path, export_dir: Path, key_id: str, private_key: str, public_key: str) -> Path:
    add_audit_event(db, finding_id=None, event_type="rotation.smoke", summary="rotation smoke", actor="smoke")
    artifact = create_integrity_proof_bundle(
        db, export_dir, actor="smoke", app_version=CURRENT_APP_VERSION,
        schema_version=CURRENT_SCHEMA_VERSION, signing_key=HMAC_KEY,
        signing_key_id=HMAC_KEY_ID, signing_keys={HMAC_KEY_ID: HMAC_KEY},
        ed25519_private_key=private_key, ed25519_public_key=public_key,
        ed25519_key_id=key_id, require_public_signature=True,
    )
    return export_dir / artifact["stored_filename"]


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow_proof_rotation_") as temp_name:
        root = Path(temp_name)
        db = root / "vulnflow.db"
        exports = root / "exports"
        init_db(db)
        checks["current_schema_42"] = validate_database_file(db)["schema_version"] == CURRENT_SCHEMA_VERSION == 46

        private = {key_id: _private_key() for key_id in ("root", "middle", "current")}
        public = {key_id: public_key_from_private(value) for key_id, value in private.items()}
        first = create_integrity_proof_key_transition(
            db, from_key_id="root", to_key_id="middle", private_keys=private, public_keys=public,
            actor="smoke", reason="root to middle rotation",
        )
        second = create_integrity_proof_key_transition(
            db, from_key_id="middle", to_key_id="current", private_keys=private, public_keys=public,
            actor="smoke", reason="middle to current rotation",
        )
        rows = list_integrity_proof_key_transitions(db)
        checks["transition_count"] = len(rows) == 2
        serialized = json.dumps(rows, ensure_ascii=False)
        checks["private_material_redacted"] = all(value not in serialized for value in private.values())
        checks["raw_reason_redacted"] = "root to middle rotation" not in serialized

        bundle = _proof(db, exports, "current", private["current"], public["current"])
        checked = verify_integrity_proof_bundle(bundle, ed25519_public_keys={"root": public["root"]})
        checks["rotated_public_key_trust"] = checked.get("trust_status") == "rotated-public-key"
        checks["multi_hop_path"] = checked.get("trust_path") == ["root", "middle", "current"]
        checks["transition_ids"] = checked.get("transition_ids") == [
            first["statement"]["transition_id"], second["statement"]["transition_id"]
        ]
        checks["proof_v3"] = checked.get("proof_format") == "vulnflow-integrity-proof/3"

        future_db = root / "future.db"
        future_exports = root / "future-exports"
        init_db(future_db)
        future = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat()
        create_integrity_proof_key_transition(
            future_db, from_key_id="root", to_key_id="current", private_keys=private, public_keys=public,
            actor="smoke", reason="future rotation", effective_at=future,
        )
        future_bundle = _proof(future_db, future_exports, "current", private["current"], public["current"])
        try:
            verify_integrity_proof_bundle(future_bundle, ed25519_public_keys={"root": public["root"]})
            checks["future_transition_blocked"] = False
        except ValueError:
            checks["future_transition_blocked"] = True

        with sqlite3.connect(db) as conn:
            try:
                conn.execute(
                    "UPDATE integrity_proof_key_transitions SET to_key_id='tampered' WHERE transition_id=?",
                    (first["statement"]["transition_id"],),
                )
                checks["immutable_transition"] = False
            except sqlite3.DatabaseError:
                checks["immutable_transition"] = True

    passed = sum(checks.values())
    total = len(checks)
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    payload = {
        "version": CURRENT_APP_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "checks": checks,
        "passed": passed,
        "total": total,
    }
    (reports / "proof_key_rotation_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow Ed25519 proof key rotation verification",
        f"version: {CURRENT_APP_VERSION}",
        f"schema_version: {CURRENT_SCHEMA_VERSION}",
        f"result: {passed}/{total}",
    ] + [f"- {name}: {'PASS' if ok else 'FAIL'}" for name, ok in checks.items()]
    (reports / "proof_key_rotation_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
