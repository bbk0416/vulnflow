from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import ipaddress
import re
from typing import Any

ROLES = {"viewer", "operator", "approver", "admin"}
ROLE_RANK = {"viewer": 10, "operator": 20, "approver": 30, "admin": 40}


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    auth_method: str = "session"
    project_ids: tuple[str, ...] = ()


def parse_api_tokens(raw_json: str) -> dict[str, dict[str, Any]]:
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
    tokens: dict[str, dict[str, Any]] = {}
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
        raw_projects = value.get("projects", [])
        if raw_projects == "*":
            projects = ("*",)
        elif raw_projects in (None, ""):
            projects = ()
        elif isinstance(raw_projects, list):
            projects = tuple(str(item or "").strip().lower() for item in raw_projects if str(item or "").strip())
            if any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", item) for item in projects):
                raise ValueError(f"{name}: projects에는 프로젝트 ID 또는 *만 사용할 수 있습니다.")
        else:
            raise ValueError(f"{name}: projects는 프로젝트 ID 배열 또는 *여야 합니다.")
        if secret in seen_secrets:
            raise ValueError("API token 값은 서로 달라야 합니다.")
        seen_secrets.add(secret)
        tokens[name] = {"token": secret, "role": role, "projects": projects}
    return tokens


def is_trusted_local_host(client_host: str) -> bool:
    host = str(client_host or "").strip().lower()
    if host in {"localhost", "testclient", "testserver"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    match: tuple[str, dict[str, Any]] | None = None
    for name, item in tokens.items():
        if hmac.compare_digest(supplied, item["token"]):
            match = (name, item)
    if match is None:
        return None
    name, item = match
    return Principal(f"api:{name}", item["role"], "bearer", tuple(item.get("projects") or ()))


def authenticate_request(
    authorization_header: str,
    *,
    api_tokens_json: str = "",
    session_token: str = "",
    db_path: Any = None,
    authenticate_session_fn: Any = None,
    allow_local_fallback: bool = False,
    client_host: str = "",
    user_agent: str = "",
    session_binding: str = "off",
    session_idle_minutes: int = 0,
    **_legacy: Any,
) -> Principal | None:
    header = str(authorization_header or "")
    if header.startswith("Bearer "):
        return authenticate_bearer(header, api_tokens_json=api_tokens_json)
    if session_token and db_path is not None and callable(authenticate_session_fn):
        principal = authenticate_session_fn(
            db_path,
            session_token,
            user_agent=user_agent,
            client_key=client_host,
            binding_mode=session_binding,
            idle_minutes=session_idle_minutes,
        )
        if principal is not None:
            return principal
    if allow_local_fallback and is_trusted_local_host(client_host):
        return Principal("local-user", "admin", "local")
    return None

def has_role(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(str(role), 0) >= ROLE_RANK.get(str(minimum), 10_000)
