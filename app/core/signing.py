from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Mapping

KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MIN_KEY_LENGTH = 16
LEGACY_AUDIT_KEY_ID = "legacy-audit"
LEGACY_BACKUP_KEY_ID = "legacy-backup"


@dataclass(frozen=True)
class SigningConfig:
    keys: dict[str, str]
    audit_active_key_id: str | None
    backup_active_key_id: str | None
    legacy_audit_key_id: str | None = None
    legacy_backup_key_id: str | None = None

    def active(self, scope: str) -> tuple[str | None, str]:
        key_id = self.audit_active_key_id if scope == "audit" else self.backup_active_key_id
        return key_id, self.keys.get(key_id or "", "")

    def public_summary(self) -> dict[str, Any]:
        return {
            "configured_key_ids": sorted(self.keys),
            "key_count": len(self.keys),
            "audit_active_key_id": self.audit_active_key_id,
            "backup_active_key_id": self.backup_active_key_id,
            "legacy_audit_configured": bool(self.legacy_audit_key_id),
            "legacy_backup_configured": bool(self.legacy_backup_key_id),
        }


def _parse_json_object(raw: str) -> dict[str, str]:
    if not str(raw or "").strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("VULNFLOW_SIGNING_KEYS_JSON은 JSON 객체여야 합니다.") from exc
    if not isinstance(parsed, dict):
        raise ValueError("VULNFLOW_SIGNING_KEYS_JSON은 JSON 객체여야 합니다.")
    output: dict[str, str] = {}
    seen_secrets: dict[str, str] = {}
    for raw_id, raw_secret in parsed.items():
        key_id = str(raw_id).strip()
        secret = str(raw_secret)
        if not KEY_ID_RE.fullmatch(key_id):
            raise ValueError(f"유효하지 않은 서명 키 ID입니다: {key_id!r}")
        if len(secret) < MIN_KEY_LENGTH:
            raise ValueError(f"서명 키 {key_id!r}는 최소 {MIN_KEY_LENGTH}자 이상이어야 합니다.")
        if secret in seen_secrets:
            raise ValueError(
                f"서명 키 {key_id!r}와 {seen_secrets[secret]!r}가 동일한 비밀값을 사용합니다. 키 ID별로 다른 값을 사용하세요."
            )
        output[key_id] = secret
        seen_secrets[secret] = key_id
    return output


def build_signing_config(
    *,
    signing_keys_json: str = "",
    audit_active_key_id: str = "",
    backup_active_key_id: str = "",
    legacy_audit_key: str = "",
    legacy_backup_key: str = "",
    require_audit: bool = False,
    require_backup: bool = False,
) -> SigningConfig:
    keys = _parse_json_object(signing_keys_json)
    legacy_audit_id: str | None = None
    legacy_backup_id: str | None = None

    def add_legacy(key_id: str, secret: str) -> str | None:
        if not secret:
            return None
        if len(secret) < MIN_KEY_LENGTH:
            raise ValueError(f"레거시 서명 키는 최소 {MIN_KEY_LENGTH}자 이상이어야 합니다.")
        # If the same secret already exists in the keyring, reuse its explicit ID.
        for existing_id, existing_secret in keys.items():
            if hmac.compare_digest(existing_secret, secret):
                return existing_id
        if key_id in keys and not hmac.compare_digest(keys[key_id], secret):
            raise ValueError(f"예약 키 ID {key_id!r}가 다른 값으로 이미 사용 중입니다.")
        keys[key_id] = secret
        return key_id

    legacy_audit_id = add_legacy(LEGACY_AUDIT_KEY_ID, legacy_audit_key)
    legacy_backup_id = add_legacy(LEGACY_BACKUP_KEY_ID, legacy_backup_key)

    audit_id = str(audit_active_key_id or "").strip() or legacy_audit_id
    backup_id = str(backup_active_key_id or "").strip() or legacy_backup_id
    if not audit_id and len(keys) == 1:
        audit_id = next(iter(keys))
    if not backup_id and len(keys) == 1:
        backup_id = next(iter(keys))

    for scope, key_id in (("감사", audit_id), ("복구", backup_id)):
        if key_id and key_id not in keys:
            raise ValueError(f"{scope} 활성 서명 키 ID {key_id!r}가 키링에 없습니다.")
    if require_audit and not audit_id:
        raise ValueError(
            "감사 서명 필수 모드에는 VULNFLOW_AUDIT_ACTIVE_KEY_ID 또는 "
            "VULNFLOW_AUDIT_SIGNING_KEY가 필요합니다."
        )
    if require_backup and not backup_id:
        raise ValueError(
            "복구 서명 필수 모드에는 VULNFLOW_BACKUP_ACTIVE_KEY_ID 또는 "
            "VULNFLOW_BACKUP_SIGNING_KEY가 필요합니다."
        )

    return SigningConfig(
        keys=dict(keys),
        audit_active_key_id=audit_id,
        backup_active_key_id=backup_id,
        legacy_audit_key_id=legacy_audit_id,
        legacy_backup_key_id=legacy_backup_id,
    )


def hmac_sha256(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_hmac(
    *,
    signature: str,
    payload: bytes,
    signing_keys: Mapping[str, str] | None = None,
    key_id: str | None = None,
    legacy_key: str = "",
) -> dict[str, Any]:
    candidates = dict(signing_keys or {})
    if legacy_key and all(not hmac.compare_digest(value, legacy_key) for value in candidates.values()):
        candidates["legacy-unidentified"] = legacy_key
    if key_id:
        secret = candidates.get(key_id)
        if secret is None:
            return {"valid": False, "status": "unknown-key-id", "resolved_key_id": None}
        valid = hmac.compare_digest(signature, hmac_sha256(secret, payload))
        return {"valid": valid, "status": "valid" if valid else "invalid", "resolved_key_id": key_id}

    matches = [candidate_id for candidate_id, secret in candidates.items()
               if hmac.compare_digest(signature, hmac_sha256(secret, payload))]
    if len(matches) == 1:
        return {"valid": True, "status": "valid", "resolved_key_id": matches[0]}
    if len(matches) > 1:
        return {"valid": False, "status": "ambiguous-key-match", "resolved_key_id": None}
    return {"valid": False, "status": "invalid", "resolved_key_id": None}


def collect_signing_key_usage(
    *,
    db_path: str,
    recovery_dir: str,
    export_dir: str = "",
    configured_key_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Return key-reference counts without exposing key material."""
    import sqlite3
    import zipfile
    from pathlib import Path

    audit_counts: dict[str, int] = {}
    with sqlite3.connect(str(db_path)) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_checkpoints)")}
        if "key_id" in columns:
            rows = conn.execute(
                "SELECT COALESCE(NULLIF(key_id,''),'legacy-unidentified') AS key_ref, COUNT(*) "
                "FROM audit_checkpoints WHERE signature IS NOT NULL GROUP BY key_ref"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT 'legacy-unidentified' AS key_ref, COUNT(*) FROM audit_checkpoints WHERE signature IS NOT NULL"
            ).fetchall()
        audit_counts = {str(key): int(count) for key, count in rows if int(count) > 0}

    recovery_counts: dict[str, int] = {}
    unreadable_bundles = 0
    root = Path(recovery_dir)
    for bundle in root.glob("vulnflow_recovery_*.zip") if root.exists() else []:
        try:
            with zipfile.ZipFile(bundle) as archive:
                manifest = json.loads(archive.read("manifest.json"))
            if not bool(manifest.get("signed")):
                continue
            signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
            key_ref = str(signature_meta.get("key_id") or "legacy-unidentified")
            recovery_counts[key_ref] = recovery_counts.get(key_ref, 0) + 1
        except Exception:
            unreadable_bundles += 1

    proof_counts: dict[str, int] = {}
    public_proof_counts: dict[str, int] = {}
    unreadable_proof_bundles = 0
    export_root = Path(export_dir) if str(export_dir or "").strip() else None
    for bundle in export_root.glob("integrity_proof_*.zip") if export_root and export_root.exists() else []:
        try:
            with zipfile.ZipFile(bundle) as archive:
                manifest = json.loads(archive.read("manifest.json"))
            signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
            if not bool(signature_meta.get("signed")):
                continue
            key_ref = str(signature_meta.get("key_id") or "legacy-unidentified")
            algorithm = str(signature_meta.get("algorithm") or "HMAC-SHA256")
            target = public_proof_counts if algorithm == "Ed25519" else proof_counts
            target[key_ref] = target.get(key_ref, 0) + 1
        except Exception:
            unreadable_proof_bundles += 1

    all_ids = set(configured_key_ids or []) | set(audit_counts) | set(recovery_counts) | set(proof_counts)
    items = []
    for key_id in sorted(all_ids):
        audit_refs = audit_counts.get(key_id, 0)
        recovery_refs = recovery_counts.get(key_id, 0)
        proof_refs = proof_counts.get(key_id, 0)
        total_refs = audit_refs + recovery_refs + proof_refs
        items.append({
            "key_id": key_id,
            "configured": key_id in set(configured_key_ids or []),
            "audit_checkpoint_refs": audit_refs,
            "recovery_bundle_refs": recovery_refs,
            "integrity_proof_refs": proof_refs,
            "total_refs": total_refs,
            "safe_to_remove": total_refs == 0,
        })
    return {
        "items": items,
        "unreadable_recovery_bundles": unreadable_bundles,
        "unreadable_integrity_proof_bundles": unreadable_proof_bundles,
        "public_integrity_proof_key_refs": dict(sorted(public_proof_counts.items())),
        "unknown_referenced_key_ids": [
            item["key_id"] for item in items if not item["configured"] and item["key_id"] != "legacy-unidentified"
        ],
    }
