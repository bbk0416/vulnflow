from __future__ import annotations

"""Read-only SMTP and Jira connectivity diagnostic facade."""

from pathlib import Path
from typing import Any

from app.repositories.collaboration import get_integration
from app.services.integration_crypto import decrypt_secret
from app.services.integration_diagnostics_common import DiagnosticResult
from app.services.integration_diagnostics_email import diagnose_email_connection
from app.services.integration_diagnostics_jira import diagnose_jira_connection


def diagnose_saved_integration(
    db_path: str | Path,
    *,
    channel: str,
    master_key: str,
    timeout_seconds: int = 10,
    allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (),
    max_response_bytes: int = 1024 * 1024,
    smtp_allow_private_networks: bool = False,
    smtp_host_allowlist: str | tuple[str, ...] = (),
    smtp_allow_plain: bool = False,
) -> dict[str, Any]:
    normalized = str(channel or "").strip().upper()
    integration = get_integration(db_path, normalized, include_secret=True)
    if not integration:
        return DiagnosticResult(
            normalized, False, "configuration", "저장된 연동 설정이 없습니다.", 0, {}
        ).as_dict()
    ciphertext = str(integration.get("secret_ciphertext") or "")
    secret = decrypt_secret(ciphertext, master_key=master_key) if ciphertext else {}
    config = dict(integration.get("config") or {})
    if normalized == "EMAIL":
        return diagnose_email_connection(
            config,
            secret,
            timeout_seconds=timeout_seconds,
            allow_private_networks=smtp_allow_private_networks,
            host_allowlist=smtp_host_allowlist,
            allow_plain=smtp_allow_plain,
        )
    if normalized == "JIRA":
        return diagnose_jira_connection(
            config,
            secret,
            timeout_seconds=timeout_seconds,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
            max_response_bytes=max_response_bytes,
        )
    return DiagnosticResult(
        normalized, False, "configuration", "지원하지 않는 연동 채널입니다.", 0, {}
    ).as_dict()


__all__ = [
    "DiagnosticResult",
    "diagnose_email_connection",
    "diagnose_jira_connection",
    "diagnose_saved_integration",
]
