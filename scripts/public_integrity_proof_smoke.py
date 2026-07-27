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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.public_signing import b64encode_raw, public_key_fingerprint
from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, add_audit_event, init_db
from app.services.integrity_proofs import create_integrity_proof_bundle, verify_integrity_proof_bundle

HMAC_KEY_ID = "public-proof-audit"
HMAC_KEY = "public-proof-audit-secret-0123456789"
ED_KEY_ID = "public-proof-ed25519-v1"


def _pair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode_raw(private_raw), b64encode_raw(public_raw)


def main() -> None:
    checks: dict[str, bool] = {}
    private_key, public_key = _pair()
    _wrong_private, wrong_public = _pair()
    with tempfile.TemporaryDirectory(prefix="vulnflow_public_integrity_proof_smoke_") as temp_name:
        temp = Path(temp_name)
        db = temp / "vulnflow.db"
        export_dir = temp / "exports"
        init_db(db)
        add_audit_event(db, finding_id=None, event_type="proof.public.smoke", summary="public proof", actor="smoke")
        artifact = create_integrity_proof_bundle(
            db, export_dir, actor="admin", app_version=CURRENT_APP_VERSION,
            schema_version=CURRENT_SCHEMA_VERSION, signing_key=HMAC_KEY,
            signing_key_id=HMAC_KEY_ID, signing_keys={HMAC_KEY_ID: HMAC_KEY},
            ed25519_private_key=private_key, ed25519_public_key=public_key,
            ed25519_key_id=ED_KEY_ID, require_public_signature=True,
        )
        bundle = export_dir / artifact["stored_filename"]
        checked = verify_integrity_proof_bundle(bundle, ed25519_public_keys={ED_KEY_ID: public_key})
        checks["pinned_public_key_verify"] = checked.get("valid") is True
        checks["ed25519_algorithm"] = checked.get("signature_algorithm") == "Ed25519"
        checks["pinned_trust"] = checked.get("trust_status") == "pinned-public-key"
        checks["fingerprint"] = checked.get("public_key_sha256") == public_key_fingerprint(public_key)
        checks["shared_secret_not_required"] = checked.get("audit", {}).get("checkpoint_signature_status") == "covered-by-ed25519-proof-not-independently-verified"
        checks["private_key_not_embedded"] = private_key.encode() not in bundle.read_bytes()
        with zipfile.ZipFile(bundle) as archive:
            checks["public_proof_files"] = {"proof.ed25519", "proof-public-key.json"}.issubset(archive.namelist()) and "proof.hmac" not in archive.namelist()
        embedded = verify_integrity_proof_bundle(bundle, allow_embedded_public_key=True)
        checks["embedded_key_marked_untrusted"] = embedded.get("trust_status") == "embedded-key-untrusted"
        try:
            verify_integrity_proof_bundle(bundle, ed25519_public_keys={ED_KEY_ID: wrong_public})
            checks["wrong_public_key_rejected"] = False
        except ValueError:
            checks["wrong_public_key_rejected"] = True
        cli = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_integrity_proof.py"), str(bundle),
             "--public-key", f"{ED_KEY_ID}={public_key}"],
            cwd=ROOT, check=False, capture_output=True, text=True, timeout=30,
        )
        checks["offline_cli_pinned"] = cli.returncode == 0 and json.loads(cli.stdout).get("trust_status") == "pinned-public-key"

    report = {
        "version": CURRENT_APP_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "checks": checks,
        "passed": sum(1 for value in checks.values() if value),
        "total": len(checks),
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "public_integrity_proof_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow public-key integrity proof verification",
        f"version: {CURRENT_APP_VERSION}",
        f"schema_version: {CURRENT_SCHEMA_VERSION}",
        "",
    ] + [f"{'PASS' if value else 'FAIL'}  {name}" for name, value in checks.items()]
    lines.extend(["", f"result: {report['passed']}/{report['total']}"])
    (reports / "public_integrity_proof_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if report["passed"] != report["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
