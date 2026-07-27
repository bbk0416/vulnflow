from __future__ import annotations

"""Ed25519 key parsing and public-verification helpers.

Private key material is accepted only as URL-safe base64 encoded 32-byte seeds.
Public summaries expose key IDs and SHA-256 fingerprints, never key material.
"""

from dataclasses import dataclass
import base64
import hashlib
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.signing import KEY_ID_RE

ED25519_ALGORITHM = "Ed25519"
RAW_KEY_BYTES = 32


def _b64decode(value: str, *, label: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label}가 비어 있습니다.")
    try:
        padding = "=" * (-len(text) % 4)
        raw = base64.urlsafe_b64decode((text + padding).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{label}는 URL-safe base64 형식이어야 합니다.") from exc
    if len(raw) != RAW_KEY_BYTES:
        raise ValueError(f"{label}는 디코딩 후 {RAW_KEY_BYTES}바이트여야 합니다.")
    return raw


def b64encode_raw(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _parse_json_object(raw: str, *, label: str) -> dict[str, str]:
    if not str(raw or "").strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label}은 JSON 객체여야 합니다.") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label}은 JSON 객체여야 합니다.")
    output: dict[str, str] = {}
    for raw_id, raw_value in parsed.items():
        key_id = str(raw_id).strip()
        if not KEY_ID_RE.fullmatch(key_id):
            raise ValueError(f"유효하지 않은 Ed25519 키 ID입니다: {key_id!r}")
        output[key_id] = str(raw_value).strip()
    return output


def public_key_from_private(private_key_base64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(
        _b64decode(private_key_base64, label="Ed25519 private key")
    )
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode_raw(raw)


def public_key_fingerprint(public_key_base64: str) -> str:
    raw = _b64decode(public_key_base64, label="Ed25519 public key")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sign_ed25519(private_key_base64: str, payload: bytes) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(
        _b64decode(private_key_base64, label="Ed25519 private key")
    )
    return b64encode_raw(private_key.sign(payload))


def verify_ed25519(*, signature_base64: str, public_key_base64: str, payload: bytes) -> bool:
    try:
        padding = "=" * (-len(str(signature_base64).strip()) % 4)
        signature = base64.urlsafe_b64decode((str(signature_base64).strip() + padding).encode("ascii"))
        if len(signature) != 64:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(
            _b64decode(public_key_base64, label="Ed25519 public key")
        )
        public_key.verify(signature, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True, slots=True)
class Ed25519SigningConfig:
    private_keys: Mapping[str, str]
    public_keys: Mapping[str, str]
    active_key_id: str | None

    def active(self) -> tuple[str | None, str, str]:
        key_id = self.active_key_id
        if not key_id:
            return None, "", ""
        return key_id, str(self.private_keys.get(key_id, "")), str(self.public_keys.get(key_id, ""))

    def public_summary(self) -> dict[str, Any]:
        return {
            "algorithm": ED25519_ALGORITHM,
            "configured_public_key_ids": sorted(self.public_keys),
            "configured_private_key_ids": sorted(self.private_keys),
            "public_key_count": len(self.public_keys),
            "private_key_count": len(self.private_keys),
            "active_key_id": self.active_key_id,
            "public_key_fingerprints": {
                key_id: public_key_fingerprint(value) for key_id, value in sorted(self.public_keys.items())
            },
        }


def build_ed25519_signing_config(
    *,
    private_keys_json: str = "",
    public_keys_json: str = "",
    active_key_id: str = "",
    require_private: bool = False,
) -> Ed25519SigningConfig:
    private_keys = _parse_json_object(
        private_keys_json, label="VULNFLOW_INTEGRITY_PROOF_PRIVATE_KEYS_JSON"
    )
    explicit_public = _parse_json_object(
        public_keys_json, label="VULNFLOW_INTEGRITY_PROOF_PUBLIC_KEYS_JSON"
    )
    public_keys: dict[str, str] = {}
    for key_id, value in explicit_public.items():
        _b64decode(value, label=f"Ed25519 public key {key_id!r}")
        public_keys[key_id] = value
    for key_id, private_value in private_keys.items():
        _b64decode(private_value, label=f"Ed25519 private key {key_id!r}")
        derived = public_key_from_private(private_value)
        if key_id in public_keys and public_keys[key_id] != derived:
            raise ValueError(f"Ed25519 키 {key_id!r}의 private/public key가 일치하지 않습니다.")
        public_keys[key_id] = derived

    selected = str(active_key_id or "").strip() or None
    if selected and not KEY_ID_RE.fullmatch(selected):
        raise ValueError(f"유효하지 않은 Ed25519 활성 키 ID입니다: {selected!r}")
    if not selected and len(private_keys) == 1:
        selected = next(iter(private_keys))
    if selected and selected not in private_keys:
        raise ValueError(f"Ed25519 활성 키 ID {selected!r}에 private key가 없습니다.")
    if require_private and not selected:
        raise ValueError("공개 검증용 proof 서명에는 활성 Ed25519 private key가 필요합니다.")
    return Ed25519SigningConfig(
        private_keys=dict(private_keys), public_keys=public_keys, active_key_id=selected
    )
