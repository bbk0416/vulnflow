from __future__ import annotations

import socket
from pathlib import Path

import pytest

from app.core.database_schema import init_db
from app.repositories.collaboration import list_collaboration_events, save_integration
from app.repositories.finding_ingestion import upsert_findings
from app.services.collaboration import (
    deliver_collaboration_events,
    queue_event_for_integrations,
    validate_email_config,
)
from app.services.integration_crypto import encrypt_secret
from app.services.integration_diagnostics import diagnose_email_connection
from app.services.outbound_http import OutboundHostTarget, OutboundPolicyError
from app.services.outbound_smtp import connect_outbound_smtp
from app.services.security_profile import evaluate_security_profile
from scripts.smtp_egress_rehearsal import run_rehearsal

MASTER = "smtp-boundary-test-master-key-1234567890"
PUBLIC_A = "93.184.216.34"


def _email_config(host: str = "smtp.example.com", security: str = "STARTTLS") -> dict:
    return {
        "host": host,
        "port": 587,
        "security": security,
        "username": "mailer",
        "from_address": "vulnflow@example.com",
        "recipients": ["security@example.com"],
        "events": ["finding.workflow_changed"],
    }


def _production_values(tmp_path: Path) -> dict:
    return {
        "SECURITY_PROFILE": "production",
        "PUBLIC_BASE_URL": "https://vulnflow.example.test",
        "COOKIE_SECURE": True,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "AUTH_SESSION_BINDING": "user-agent",
        "AUTH_SESSION_IDLE_MINUTES": 30,
        "EVIDENCE_REQUIRE_CLEAN": True,
        "EVIDENCE_SCANNER_MODE": "builtin",
        "AUDIT_REQUIRE_SIGNATURE": True,
        "AUDIT_SIGNING_KEY": "audit-signing-key",
        "BACKUP_REQUIRE_SIGNATURE": True,
        "BACKUP_SIGNING_KEY": "backup-signing-key",
        "CURSOR_SIGNING_KEY_CONFIGURED": True,
        "BACKUP_INTERVAL_HOURS": 12,
        "EXTERNAL_BACKUP_DIR": tmp_path / "external",
    }


def test_smtp_private_mixed_dns_and_allowlist_are_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_A, 587)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 587)),
        ],
    )
    with pytest.raises(OutboundPolicyError, match="blocked network"):
        connect_outbound_smtp("smtp.example.com", 587, security="STARTTLS")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_A, 587)),
        ],
    )
    with pytest.raises(OutboundPolicyError, match="allowlisted"):
        connect_outbound_smtp(
            "smtp.example.com", 587, security="STARTTLS",
            host_allowlist="mail.example.com",
        )


def test_smtp_uses_validated_address_and_original_tls_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    class FakeSMTP:
        def __init__(self, hostname, address, port, *, timeout):
            observed.update(hostname=hostname, address=address, port=port, timeout=timeout)
        def ehlo(self):
            return 250, b"ok"
        def starttls(self, context=None):
            observed["starttls"] = context is not None
            return 220, b"ready"
        def close(self):
            return None

    monkeypatch.setattr(
        "app.services.outbound_smtp.resolve_outbound_host",
        lambda *args, **kwargs: OutboundHostTarget("smtp.example.com", 587, (PUBLIC_A,)),
    )
    monkeypatch.setattr("app.services.outbound_smtp._PinnedSMTP", FakeSMTP)
    server = connect_outbound_smtp(
        "smtp.example.com", 587, security="STARTTLS",
        host_allowlist="smtp.example.com",
    )
    assert server is not None
    assert observed == {
        "hostname": "smtp.example.com",
        "address": PUBLIC_A,
        "port": 587,
        "timeout": 10.0,
        "starttls": True,
    }


def test_plain_smtp_and_header_injection_are_rejected() -> None:
    with pytest.raises(OutboundPolicyError, match="unencrypted"):
        connect_outbound_smtp(
            "smtp.example.com", 25, security="PLAIN",
            host_allowlist="smtp.example.com",
        )
    with pytest.raises(ValueError, match="발신"):
        validate_email_config(
            {**_email_config(), "from_address": "safe@example.com\r\nBcc: attacker@example.com"},
            secret_configured=True,
        )
    with pytest.raises(ValueError, match="수신"):
        validate_email_config(
            {**_email_config(), "recipients": ["safe@example.com\nCc: attacker@example.com"]},
            secret_configured=True,
        )


def test_private_smtp_delivery_is_permanent_policy_failure(tmp_path: Path) -> None:
    db = tmp_path / "smtp.sqlite3"
    init_db(db)
    upsert_findings(
        db,
        [{
            "finding_id": "F-SMTP",
            "product": "OpenSSL",
            "cve_id": "CVE-2026-90001",
            "asset_name": "server-01",
            "status": "IN_PROGRESS",
        }],
        actor="test",
    )
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config=validate_email_config(
            _email_config("127.0.0.1"), secret_configured=True
        ),
        secret_ciphertext=encrypt_secret({"password": "smtp-secret"}, master_key=MASTER),
        actor="admin",
    )
    queue_event_for_integrations(
        db,
        event_type="finding.workflow_changed",
        payload={"finding_id": "F-SMTP"},
        actor="operator",
    )
    result = deliver_collaboration_events(db, master_key=MASTER, due_soon_days=0)
    assert result["failed"] == 1
    event = list_collaboration_events(db)[0]
    assert event["status"] == "FAILED"
    assert "OutboundPolicyError" in event["last_error"]


def test_smtp_diagnostic_reports_policy_without_connecting() -> None:
    result = diagnose_email_connection(
        _email_config("127.0.0.1"), {"password": "smtp-secret"}
    )
    assert result["ok"] is False
    assert result["stage"] == "outbound_policy"
    assert "smtp-secret" not in str(result)


def test_production_profile_forbids_plain_and_requires_private_smtp_allowlist(tmp_path: Path) -> None:
    values = _production_values(tmp_path)
    values.update({
        "SMTP_ALLOW_PLAIN": True,
        "SMTP_ALLOW_PRIVATE_NETWORKS": True,
        "SMTP_HOST_ALLOWLIST": "",
    })
    report = evaluate_security_profile(values, tokens={})
    codes = {item.code for item in report.findings}
    assert {"smtp.plain", "smtp.allowlist"} <= codes

    values["SMTP_ALLOW_PLAIN"] = False
    values["SMTP_HOST_ALLOWLIST"] = "smtp.internal.example"
    report = evaluate_security_profile(values, tokens={})
    codes = {item.code for item in report.findings}
    assert "smtp.plain" not in codes
    assert "smtp.allowlist" not in codes


def test_live_smtp_starttls_rehearsal() -> None:
    report = run_rehearsal()
    assert report["passed"] is True
    assert report["checks"]["tls_sni_original_hostname"] is True
    assert report["checks"]["message_delivered"] is True
