from __future__ import annotations

"""Database-backed users, password verification, and opaque browser sessions."""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets
import unicodedata
from pathlib import Path
from typing import Any

from app.core.auth import Principal, ROLES
from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+\-]{2,63}$")
_PASSWORD_PREFIX = "vulnflow-scrypt-v1"
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_DUMMY_PASSWORD_HASH = (
    "vulnflow-scrypt-v1$16384$8$1$"
    "MDEyMzQ1Njc4OWFiY2RlZg==$"
    "MU2GUf2fVRE2JH55+rqS8l8QVx3SZ88k9LdDfUT69uU="
)


@dataclass(frozen=True, slots=True)
class PasswordAuthentication:
    status: str
    principal: Principal | None = None
    retry_after_seconds: int = 0
    locked_until: str = ""  # legacy compatibility; account-wide lockouts are no longer used


def _utc_datetime(value: str = "") -> datetime:
    text = str(value or "").strip()
    if text:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def normalize_username(username: str) -> str:
    value = unicodedata.normalize("NFKC", str(username or "")).strip().lower()
    if not _USERNAME_RE.fullmatch(value):
        raise ValueError(
            "사용자 이름은 영문자 또는 숫자로 시작하는 3~64자의 영문자, 숫자, ., _, @, +, -만 사용할 수 있습니다."
        )
    return value


def validate_password(password: str) -> str:
    value = str(password or "")
    if len(value) < 12:
        raise ValueError("비밀번호는 최소 12자여야 합니다.")
    if len(value) > 256:
        raise ValueError("비밀번호는 최대 256자까지 사용할 수 있습니다.")
    if value.strip() != value:
        raise ValueError("비밀번호 앞뒤에 공백을 사용할 수 없습니다.")
    categories = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    if categories < 3:
        raise ValueError("비밀번호에는 영문 대문자·소문자·숫자·특수문자 중 3종류 이상을 포함하세요.")
    return value


def hash_password(password: str) -> str:
    value = validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        value.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return "$".join(
        (
            _PASSWORD_PREFIX,
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, n_text, r_text, p_text, salt_text, digest_text = str(encoded or "").split("$", 5)
        if prefix != _PASSWORD_PREFIX:
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        if n < (1 << 14) or n > (1 << 18) or r < 1 or r > 32 or p < 1 or p > 8:
            return False
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(digest_text, validate=True)
        if len(salt) < 16 or len(expected) != _SCRYPT_DKLEN:
            return False
        actual = hashlib.scrypt(
            str(password or "").encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _session_hash(raw_token: str) -> str:
    return hashlib.sha256(str(raw_token or "").encode("utf-8")).hexdigest()


def _fingerprint(value: str) -> str:
    text = str(value or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def count_active_users(db_path: str | Path) -> int:
    with read_connection(db_path, operation="count_active_users") as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM app_users WHERE is_active=1").fetchone()
    return int(row["count"] if row else 0)


def get_user(db_path: str | Path, username: str) -> dict[str, Any] | None:
    try:
        normalized = normalize_username(username)
    except ValueError:
        return None
    with read_connection(db_path, operation="get_user") as conn:
        row = conn.execute(
            """SELECT username,role,is_active,failed_attempts,locked_until,last_login_at,
                      password_changed_at,created_by,created_at,updated_at
                 FROM app_users WHERE username=?""",
            (normalized,),
        ).fetchone()
    return dict(row) if row else None


def list_users(db_path: str | Path) -> list[dict[str, Any]]:
    with read_connection(db_path, operation="list_users") as conn:
        rows = conn.execute(
            """SELECT u.username,u.role,u.is_active,u.failed_attempts,u.locked_until,
                      u.last_login_at,u.password_changed_at,u.created_by,u.created_at,u.updated_at,
                      SUM(CASE WHEN s.revoked_at='' AND s.expires_at>? THEN 1 ELSE 0 END) AS active_sessions
                 FROM app_users u
                 LEFT JOIN auth_sessions s ON s.username=u.username
                GROUP BY u.username
                ORDER BY CASE u.role WHEN 'admin' THEN 0 WHEN 'approver' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END,
                         u.username""",
            (utc_now(),),
        ).fetchall()
    return [dict(row) for row in rows]


def create_user(
    db_path: str | Path,
    *,
    username: str,
    password: str,
    role: str,
    actor: str,
) -> dict[str, Any]:
    normalized = normalize_username(username)
    normalized_role = str(role or "viewer").strip().lower()
    if normalized_role not in ROLES:
        raise ValueError(f"지원하지 않는 역할입니다: {normalized_role}")
    encoded = hash_password(password)
    now = utc_now()
    with write_transaction(db_path, operation="create_user") as conn:
        exists = conn.execute("SELECT 1 FROM app_users WHERE username=?", (normalized,)).fetchone()
        if exists:
            raise ValueError("이미 존재하는 사용자 이름입니다.")
        conn.execute(
            """INSERT INTO app_users(
                   username,password_hash,role,is_active,failed_attempts,locked_until,last_login_at,
                   password_changed_at,created_by,created_at,updated_at
               ) VALUES(?,?,?,1,0,'','',?,?,?,?)""",
            (normalized, encoded, normalized_role, now, str(actor or "system"), now, now),
        )
        if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='projects'"
        ).fetchone():
            default_row = conn.execute(
                "SELECT project_id FROM projects WHERE is_default=1 LIMIT 1"
            ).fetchone()
            if default_row:
                conn.execute(
                    """INSERT OR IGNORE INTO project_memberships(project_id,username,created_by,created_at)
                       VALUES(?,?,?,?)""",
                    (default_row["project_id"], normalized, str(actor or "system"), now),
                )
    return get_user(db_path, normalized) or {}


def set_user_active(
    db_path: str | Path,
    *,
    username: str,
    active: bool,
    actor: str,
) -> dict[str, Any]:
    normalized = normalize_username(username)
    with write_transaction(db_path, operation="set_user_active") as conn:
        row = conn.execute("SELECT role,is_active FROM app_users WHERE username=?", (normalized,)).fetchone()
        if not row:
            raise KeyError(normalized)
        if not active and row["role"] == "admin" and int(row["is_active"]):
            admin_count = conn.execute(
                "SELECT COUNT(*) AS count FROM app_users WHERE role='admin' AND is_active=1"
            ).fetchone()["count"]
            if int(admin_count) <= 1:
                raise ValueError("마지막 활성 관리자 계정은 비활성화할 수 없습니다.")
        now = utc_now()
        conn.execute(
            "UPDATE app_users SET is_active=?,updated_at=? WHERE username=?",
            (1 if active else 0, now, normalized),
        )
        if not active:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=? WHERE username=? AND revoked_at=''",
                (now, normalized),
            )
    return get_user(db_path, normalized) or {}


def set_user_password(
    db_path: str | Path,
    *,
    username: str,
    password: str,
    actor: str,
) -> dict[str, Any]:
    normalized = normalize_username(username)
    encoded = hash_password(password)
    now = utc_now()
    with write_transaction(db_path, operation="set_user_password") as conn:
        row = conn.execute("SELECT 1 FROM app_users WHERE username=?", (normalized,)).fetchone()
        if not row:
            raise KeyError(normalized)
        conn.execute(
            """UPDATE app_users
                  SET password_hash=?,failed_attempts=0,locked_until='',password_changed_at=?,updated_at=?
                WHERE username=?""",
            (encoded, now, now, normalized),
        )
        conn.execute(
            "UPDATE auth_sessions SET revoked_at=? WHERE username=? AND revoked_at=''",
            (now, normalized),
        )
    return get_user(db_path, normalized) or {}


def unlock_user(db_path: str | Path, *, username: str, actor: str) -> dict[str, Any]:
    """Clear legacy lock fields and recent failed-attempt limiter records."""
    normalized = normalize_username(username)
    with write_transaction(db_path, operation="unlock_user") as conn:
        result = conn.execute(
            "UPDATE app_users SET failed_attempts=0,locked_until='',updated_at=? WHERE username=?",
            (utc_now(), normalized),
        )
        if result.rowcount != 1:
            raise KeyError(normalized)
        conn.execute(
            "DELETE FROM auth_login_attempts WHERE username_key=? AND succeeded=0",
            (_fingerprint(normalized),),
        )
    return get_user(db_path, normalized) or {}


def authenticate_user_password(
    db_path: str | Path,
    *,
    username: str,
    password: str,
    client_key: str = "",
    rate_window_seconds: int = 300,
    username_client_attempts: int = 5,
    client_attempts: int = 25,
    lock_threshold: int | None = None,
    lock_minutes: int | None = None,
) -> PasswordAuthentication:
    """Authenticate without exposing accounts to global lockout denial-of-service.

    Failed attempts are limited in a sliding window for the username/client pair
    and for the client as a whole.  A correct password is always evaluated before
    the failure limiter so failures generated by another client cannot lock out a
    legitimate user.  ``lock_threshold`` and ``lock_minutes`` remain accepted for
    source compatibility and map to the pair limit/window when supplied.
    """
    try:
        normalized = normalize_username(username)
    except ValueError:
        normalized = "invalid"
    if lock_threshold is not None:
        username_client_attempts = lock_threshold
    if lock_minutes is not None:
        rate_window_seconds = int(lock_minutes) * 60
    pair_limit = max(3, min(int(username_client_attempts), 100))
    total_limit = max(3, min(int(client_attempts), 1000))
    window_seconds = max(30, min(int(rate_window_seconds), 86400))
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    cutoff = (now_dt - timedelta(seconds=window_seconds)).isoformat()
    username_key = _fingerprint(normalized)
    normalized_client = str(client_key or "unknown-client").strip() or "unknown-client"
    client_hash = _fingerprint(normalized_client)

    with write_transaction(db_path, operation="authenticate_user_password") as conn:
        row = conn.execute(
            "SELECT username,password_hash,role,is_active FROM app_users WHERE username=?",
            (normalized,),
        ).fetchone()
        encoded = str(row["password_hash"]) if row else _DUMMY_PASSWORD_HASH
        valid = verify_password(password, encoded)

        if row is not None and valid and int(row["is_active"]):
            conn.execute(
                """UPDATE app_users
                      SET failed_attempts=0,locked_until='',last_login_at=?,updated_at=?
                    WHERE username=?""",
                (now, now, normalized),
            )
            conn.execute(
                "DELETE FROM auth_login_attempts WHERE username_key=? AND client_key=? AND succeeded=0",
                (username_key, client_hash),
            )
            conn.execute(
                "INSERT INTO auth_login_attempts(username_key,client_key,succeeded,created_at) VALUES(?,?,1,?)",
                (username_key, client_hash, now),
            )
            return PasswordAuthentication(
                "ok", Principal(str(row["username"]), str(row["role"]), "session")
            )

        pair_failures = int(
            conn.execute(
                """SELECT COUNT(*) FROM auth_login_attempts
                     WHERE username_key=? AND client_key=? AND succeeded=0 AND created_at>=?""",
                (username_key, client_hash, cutoff),
            ).fetchone()[0]
        )
        client_failures = int(
            conn.execute(
                """SELECT COUNT(*) FROM auth_login_attempts
                     WHERE client_key=? AND succeeded=0 AND created_at>=?""",
                (client_hash, cutoff),
            ).fetchone()[0]
        )
        conn.execute(
            "INSERT INTO auth_login_attempts(username_key,client_key,succeeded,created_at) VALUES(?,?,0,?)",
            (username_key, client_hash, now),
        )
        if row is not None:
            # Remove stale global-lock state written by releases before schema 45.
            conn.execute(
                "UPDATE app_users SET failed_attempts=0,locked_until='',updated_at=? WHERE username=?",
                (now, normalized),
            )

        if pair_failures + 1 >= pair_limit or client_failures + 1 >= total_limit:
            return PasswordAuthentication(
                "rate_limited", retry_after_seconds=window_seconds
            )
        if row is not None and not int(row["is_active"]):
            return PasswordAuthentication("inactive")
        return PasswordAuthentication("invalid")


def create_session(
    db_path: str | Path,
    *,
    username: str,
    user_agent: str = "",
    client_key: str = "",
    lifetime_minutes: int = 480,
    max_active_sessions: int = 10,
) -> tuple[str, str]:
    normalized = normalize_username(username)
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    expires_at = (now_dt + timedelta(minutes=max(15, min(int(lifetime_minutes), 10080)))).isoformat()
    raw_token = secrets.token_urlsafe(32)
    token_hash = _session_hash(raw_token)
    session_limit = max(1, min(int(max_active_sessions), 50))
    with write_transaction(db_path, operation="create_session") as conn:
        row = conn.execute(
            "SELECT is_active FROM app_users WHERE username=?", (normalized,)
        ).fetchone()
        if not row or not int(row["is_active"]):
            raise ValueError("활성 사용자 계정을 찾을 수 없습니다.")
        conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at<=? OR (revoked_at!='' AND revoked_at<?)",
            (now, (now_dt - timedelta(days=7)).isoformat()),
        )
        conn.execute(
            """INSERT INTO auth_sessions(
                   session_hash,username,created_at,last_seen_at,expires_at,revoked_at,user_agent_hash,client_hash
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                token_hash,
                normalized,
                now,
                now,
                expires_at,
                "",
                _fingerprint(user_agent),
                _fingerprint(client_key),
            ),
        )
        active = conn.execute(
            """SELECT session_hash FROM auth_sessions
                WHERE username=? AND revoked_at='' AND expires_at>?
                ORDER BY created_at DESC, rowid DESC""",
            (normalized, now),
        ).fetchall()
        for stale in active[session_limit:]:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=? WHERE session_hash=?",
                (now, stale["session_hash"]),
            )
    return raw_token, expires_at


def authenticate_session(
    db_path: str | Path,
    raw_token: str,
    *,
    user_agent: str = "",
    client_key: str = "",
    binding_mode: str = "off",
    idle_minutes: int = 0,
) -> Principal | None:
    token = str(raw_token or "").strip()
    if len(token) < 32:
        return None
    mode = str(binding_mode or "off").strip().lower()
    if mode not in {"off", "user-agent", "strict"}:
        return None
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    token_hash = _session_hash(token)
    with read_connection(db_path, operation="authenticate_session") as conn:
        row = conn.execute(
            """SELECT u.username,u.role,u.is_active,s.expires_at,s.revoked_at,
                      s.last_seen_at,s.user_agent_hash,s.client_hash
                 FROM auth_sessions s
                 JOIN app_users u ON u.username=s.username
                WHERE s.session_hash=?""",
            (token_hash,),
        ).fetchone()
    if not row or not int(row["is_active"]) or str(row["revoked_at"] or ""):
        return None
    expired = _utc_datetime(str(row["expires_at"] or "")) <= now_dt
    idle_limit = max(0, int(idle_minutes or 0))
    last_seen = _utc_datetime(str(row["last_seen_at"] or ""))
    idle_expired = idle_limit > 0 and last_seen + timedelta(minutes=idle_limit) <= now_dt
    expected_user_agent = str(row["user_agent_hash"] or "")
    expected_client = str(row["client_hash"] or "")
    binding_failed = False
    if mode in {"user-agent", "strict"}:
        binding_failed = not expected_user_agent or not hmac.compare_digest(
            expected_user_agent, _fingerprint(user_agent)
        )
    if mode == "strict":
        binding_failed = binding_failed or not expected_client or not hmac.compare_digest(
            expected_client, _fingerprint(client_key)
        )
    if expired or idle_expired or binding_failed:
        with write_transaction(db_path, operation="revoke_invalid_session") as conn:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=? WHERE session_hash=? AND revoked_at=''",
                (now, token_hash),
            )
        return None
    if last_seen + timedelta(seconds=60) <= now_dt:
        with write_transaction(db_path, operation="touch_auth_session") as conn:
            updated = conn.execute(
                "UPDATE auth_sessions SET last_seen_at=? WHERE session_hash=? AND revoked_at=''",
                (now, token_hash),
            )
        if updated.rowcount != 1:
            return None
    return Principal(str(row["username"]), str(row["role"]), "session")


def revoke_session(db_path: str | Path, raw_token: str) -> bool:
    token = str(raw_token or "").strip()
    if not token:
        return False
    with write_transaction(db_path, operation="revoke_session") as conn:
        result = conn.execute(
            "UPDATE auth_sessions SET revoked_at=? WHERE session_hash=? AND revoked_at=''",
            (utc_now(), _session_hash(token)),
        )
    return result.rowcount == 1


def revoke_user_sessions(db_path: str | Path, username: str) -> int:
    normalized = normalize_username(username)
    with write_transaction(db_path, operation="revoke_user_sessions") as conn:
        result = conn.execute(
            "UPDATE auth_sessions SET revoked_at=? WHERE username=? AND revoked_at=''",
            (utc_now(), normalized),
        )
    return int(result.rowcount)


def prune_auth_records(db_path: str | Path, *, attempt_retention_days: int = 30) -> dict[str, int]:
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    attempts_before = (now_dt - timedelta(days=max(1, int(attempt_retention_days)))).isoformat()
    revoked_before = (now_dt - timedelta(days=7)).isoformat()
    with write_transaction(db_path, operation="prune_auth_records") as conn:
        sessions = conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at<=? OR (revoked_at!='' AND revoked_at<?)",
            (now, revoked_before),
        ).rowcount
        attempts = conn.execute(
            "DELETE FROM auth_login_attempts WHERE created_at<?", (attempts_before,)
        ).rowcount
    return {"sessions": int(sessions), "login_attempts": int(attempts)}
