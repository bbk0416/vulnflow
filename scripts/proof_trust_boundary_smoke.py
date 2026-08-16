from __future__ import annotations

import ast
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import CURRENT_APP_VERSION, init_db
from app.core.public_signing import b64encode_raw, public_key_from_private
from app.services import proof_transitions, proof_trust, proof_trust_resolver


def _private_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64encode_raw(raw)


def main() -> int:
    checks: dict[str, bool] = {}
    checks["version_72_0_7"] = CURRENT_APP_VERSION == "72.0.88"
    checks["facade_create_identity"] = proof_trust.create_integrity_proof_key_transition is proof_transitions.create_integrity_proof_key_transition
    checks["facade_validate_identity"] = proof_trust.validate_transition_document is proof_transitions.validate_transition_document
    checks["facade_resolver_identity"] = proof_trust.resolve_trusted_proof_signer is proof_trust_resolver.resolve_trusted_proof_signer

    importers: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "app/services/proof_trust.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.services.proof_trust":
                importers.append(relative)
            elif isinstance(node, ast.Import) and any(alias.name == "app.services.proof_trust" for alias in node.names):
                importers.append(relative)
    checks["internal_facade_importers_zero"] = not importers

    with tempfile.TemporaryDirectory(prefix="vulnflow-proof-trust-") as tmp:
        db = Path(tmp) / "proof.sqlite3"
        init_db(db)
        private = {"root": _private_key(), "current": _private_key()}
        public = {key_id: public_key_from_private(value) for key_id, value in private.items()}
        document = proof_transitions.create_integrity_proof_key_transition(
            db,
            from_key_id="root",
            to_key_id="current",
            private_keys=private,
            public_keys=public,
            actor="smoke",
            reason="proof trust boundary smoke",
        )
        validated = proof_transitions.validate_transition_document(document)
        exported = proof_transitions.export_integrity_proof_key_transitions(db)
        resolved = proof_trust_resolver.resolve_trusted_proof_signer(
            target_key_id="current",
            target_public_key=public["current"],
            transitions=exported,
            pinned_public_keys={"root": public["root"]},
            proof_created_at=document["statement"]["created_at"],
        )
        checks["direct_create"] = validated["to_key_id"] == "current"
        checks["direct_export"] = len(exported) == 1
        checks["direct_resolve"] = bool(resolved and resolved.get("trust_status") == "rotated-public-key")
        checks["trust_path"] = bool(resolved and resolved.get("trust_path") == ["root", "current"])
        checks["facade_list"] = len(proof_trust.list_integrity_proof_key_transitions(db)) == 1

    report = {
        "title": "VulnFlow 72.0.88 proof trust boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "internal_facade_importers": importers,
    }
    (ROOT / "reports" / "proof_trust_boundary_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [report["title"], f"version: {CURRENT_APP_VERSION}", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    lines.append("")
    lines.append(f"result: {report['passed']}/{report['total']}")
    (ROOT / "reports" / "proof_trust_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
