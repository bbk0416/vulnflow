from __future__ import annotations

import base64
from dataclasses import dataclass
import hmac
import json
import ipaddress
from typing import Any

ROLES = {"viewer", "operator", "approver", "admin"}
ROLE_RANK = {"viewer": 10, "operator": 20, "approver": 30, "admin": 40}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    auth_method: str = "basic"


def parse_accounts(raw_json: str) -> dict[str, dict[str, str]]:
    text = str(raw_json or "").strip()
    if not text:
        return {}
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("VULNFLOW_USERS_JSON이 올바른 JSON이 아닙니다.") from exc
    if not isinstance(payload, dict):
        raise ValueError("VULNFLOW_USERS_JSON은 사용자 이름을 키로 하는 객체여야 합니다.")
    accounts: dict[str, dict[str, str]] = {}
    for username, value in payload.items():
        name = str(username or "").strip()
        if not name or not isinstance(value, dict):
            raise ValueError("각 사용자 항목에는 password와 role이 필요합니다.")
        password = str(value.get("password") or "")
        role = str(value.get("role") or "viewer").strip().lower()
        if not password:
            raise ValueError(f"{name}: password가 비어 있습니다.")
        if role not in ROLES:
            raise ValueError(f"{name}: 지원하지 않는 role입니다: {role}")
        accounts[name] = {"password": password, "role": role}
    return accounts


def parse_api_tokens(raw_json: str) -> dict[str, dict[str, str]]:
    """Parse named API tokens from environment JSON.

    Expected shape::

        {"scanner-ci": {"token": "long-secret", "role": "operator"}}
    """
    text = str(raw_json or "").strip()
    if not text:
        return {}
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("VULNFLOW_API_TOKENS_JSON이 올바른 JSON이 아닙니다.") from exc
    if not isinstance(payload, dict):
        raise ValueError("VULNFLOW_API_TOKENS_JSON은 토큰 이름을 키로 하는 객체여야 합니다.")
    tokens: dict[str, dict[str, str]] = {}
    seen_secrets: set[str] = set()
    for token_name, value in payload.items():
        name = str(token_name or "").strip()
        if not name or not isinstance(value, dict):
            raise ValueError("각 API 토큰 항목에는 token과 role이 필요합니다.")
        secret = str(value.get("token") or "")
        role = str(value.get("role") or "viewer").strip().lower()
        if len(secret) < 16:
            raise ValueError(f"{name}: API token은 최소 16자여야 합니다.")
        if role not in ROLES:
            raise ValueError(f"{name}: 지원하지 않는 role입니다: {role}")
        if secret in seen_secrets:
            raise ValueError("API token 값은 서로 달라야 합니다.")
        seen_secrets.add(secret)
        tokens[name] = {"token": secret, "role": role}
    return tokens


def is_trusted_local_host(client_host: str) -> bool:
    host = str(client_host or "").strip().lower()
    if host in {"localhost", "testclient", "testserver"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def authenticate_basic(
    authorization_header: str,
    *,
    users_json: str = "",
    legacy_user: str = "",
    legacy_password: str = "",
    allow_local_fallback: bool = False,
    client_host: str = "",
) -> Principal | None:
    accounts = parse_accounts(users_json)
    if not accounts and legacy_user and legacy_password:
        accounts = {legacy_user: {"password": legacy_password, "role": "admin"}}
    if not accounts:
        return (
            Principal("local-user", "admin", "local")
            if allow_local_fallback and is_trusted_local_host(client_host)
            else None
        )
    header = str(authorization_header or "")
    if not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return None
    account = accounts.get(username)
    if not account:
        return None
    if not hmac.compare_digest(password, account["password"]):
        return None
    return Principal(username, account["role"], "basic")


def authenticate_bearer(authorization_header: str, *, api_tokens_json: str = "") -> Principal | None:
    tokens = parse_api_tokens(api_tokens_json)
    if not tokens:
        return None
    header = str(authorization_header or "")
    if not header.startswith("Bearer "):
        return None
    supplied = header[7:].strip()
    if not supplied:
        return None
    # Compare every configured value to reduce token-name timing leakage.
    match: tuple[str, dict[str, str]] | None = None
    for name, item in tokens.items():
        if hmac.compare_digest(supplied, item["token"]):
            match = (name, item)
    if match is None:
        return None
    name, item = match
    return Principal(f"api:{name}", item["role"], "bearer")


def authenticate_request(
    authorization_header: str,
    *,
    users_json: str = "",
    api_tokens_json: str = "",
    legacy_user: str = "",
    legacy_password: str = "",
    allow_local_fallback: bool = False,
    client_host: str = "",
) -> Principal | None:
    header = str(authorization_header or "")
    if header.startswith("Bearer "):
        return authenticate_bearer(header, api_tokens_json=api_tokens_json)
    return authenticate_basic(
        header,
        users_json=users_json,
        legacy_user=legacy_user,
        legacy_password=legacy_password,
        allow_local_fallback=allow_local_fallback,
        client_host=client_host,
    )


def has_role(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(str(role), 0) >= ROLE_RANK.get(str(minimum), 10_000)
