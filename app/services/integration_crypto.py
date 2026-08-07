from __future__ import annotations

"""Encrypt project integration credentials with an operator-supplied master key."""

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class IntegrationSecretError(ValueError):
    pass


def _fernet(master_key: str) -> Fernet:
    value = str(master_key or "")
    if len(value) < 32:
        raise IntegrationSecretError(
            "VULNFLOW_INTEGRATION_SECRET_KEY는 최소 32자여야 합니다."
        )
    derived = base64.urlsafe_b64encode(hashlib.sha256(value.encode("utf-8")).digest())
    return Fernet(derived)


def encrypt_secret(payload: dict[str, Any], *, master_key: str) -> str:
    clean = {str(key): str(value) for key, value in payload.items() if str(value)}
    if not clean:
        return ""
    body = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet(master_key).encrypt(body).decode("ascii")


def decrypt_secret(ciphertext: str, *, master_key: str) -> dict[str, str]:
    text = str(ciphertext or "").strip()
    if not text:
        return {}
    try:
        body = _fernet(master_key).decrypt(text.encode("ascii"))
        decoded = json.loads(body.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationSecretError("연동 비밀정보를 복호화할 수 없습니다.") from exc
    if not isinstance(decoded, dict):
        raise IntegrationSecretError("연동 비밀정보 형식이 올바르지 않습니다.")
    return {str(key): str(value) for key, value in decoded.items()}
