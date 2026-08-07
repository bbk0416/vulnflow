from __future__ import annotations

import sqlite3
from pathlib import Path

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.repositories.collaboration import (
    get_finding_external_link,
    get_integration,
    list_collaboration_events,
    queue_collaboration_event,
    record_collaboration_delivery,
    save_integration,
)
from app.repositories.finding_ingestion import upsert_findings
from app.services.collaboration import (
    deliver_collaboration_events,
    enqueue_due_reminders,
    queue_event_for_integrations,
    queue_jira_issue_create,
    validate_email_config,
    validate_jira_config,
)
from app.services.integration_crypto import decrypt_secret, encrypt_secret

MASTER = "integration-master-key-for-tests-1234567890"


def _finding(fid: str = "F-COLLAB") -> dict:
    return {
        "finding_id": fid,
        "product": "OpenSSL",
        "cve_id": "CVE-2026-80001",
        "asset_name": "server-01",
        "component": "openssl",
        "component_version": "3.0.0",
        "status": "IN_PROGRESS",
        "owner": "infra-team",
        "due_date": "2026-08-05",
    }


def _db(tmp_path: Path) -> Path:
    db = tmp_path / "collaboration.sqlite3"
    init_db(db)
    upsert_findings(db, [_finding()], actor="test")
    return db


def test_schema_43_contains_project_collaboration_tables(tmp_path: Path):
    db = _db(tmp_path)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 46
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"collaboration_integrations", "collaboration_events", "finding_external_links"} <= tables


def test_integration_secrets_are_encrypted_and_not_returned(tmp_path: Path):
    db = _db(tmp_path)
    cipher = encrypt_secret({"password": "smtp-secret"}, master_key=MASTER)
    assert "smtp-secret" not in cipher
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config={"host": "smtp.example.com"},
        secret_ciphertext=cipher,
        actor="admin",
    )
    stored = get_integration(db, "EMAIL")
    assert stored and stored["secret_configured"] is True
    assert "password" not in stored
    assert "secret_ciphertext" not in stored
    with sqlite3.connect(db) as conn:
        encrypted = conn.execute(
            "SELECT secret_ciphertext FROM collaboration_integrations WHERE channel='EMAIL'"
        ).fetchone()[0]
    assert decrypt_secret(encrypted, master_key=MASTER)["password"] == "smtp-secret"


def test_workflow_event_queues_email_and_only_comments_linked_jira(tmp_path: Path):
    db = _db(tmp_path)
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config={"events": ["finding.workflow_changed"]},
        secret_ciphertext="",
        actor="admin",
    )
    save_integration(
        db,
        channel="JIRA",
        enabled=True,
        config={"events": ["finding.workflow_changed"]},
        secret_ciphertext=encrypt_secret({"api_token": "jira-secret"}, master_key=MASTER),
        actor="admin",
    )
    queued = queue_event_for_integrations(
        db,
        event_type="finding.workflow_changed",
        payload={"finding_id": "F-COLLAB", "status": "IN_PROGRESS"},
        actor="operator",
        app_base_url="https://vulnflow.example",
    )
    assert len(queued) == 1
    assert list_collaboration_events(db)[0]["channel"] == "EMAIL"


def test_email_delivery_uses_smtp_without_storing_plaintext(tmp_path: Path, monkeypatch):
    db = _db(tmp_path)
    config = validate_email_config(
        {
            "host": "smtp.example.com",
            "port": 587,
            "security": "STARTTLS",
            "username": "mailer",
            "from_address": "vulnflow@example.com",
            "recipients": ["security@example.com"],
            "events": ["finding.workflow_changed"],
        },
        secret_configured=True,
    )
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config=config,
        secret_ciphertext=encrypt_secret({"password": "smtp-secret"}, master_key=MASTER),
        actor="admin",
    )
    queue_event_for_integrations(
        db,
        event_type="finding.workflow_changed",
        payload={"finding_id": "F-COLLAB", "status": "MITIGATED"},
        actor="operator",
    )
    sent = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def starttls(self, context=None):
            return None
        def login(self, username, password):
            assert username == "mailer" and password == "smtp-secret"
        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr(
        "app.services.collaboration.connect_outbound_smtp",
        lambda *args, **kwargs: FakeSMTP(),
    )
    result = deliver_collaboration_events(db, master_key=MASTER, due_soon_days=0)
    assert result["delivered"] == 1
    assert len(sent) == 1
    assert "F-COLLAB" in sent[0]["Subject"]


def test_jira_issue_creation_and_followup_comment(tmp_path: Path, monkeypatch):
    db = _db(tmp_path)
    config = validate_jira_config(
        {
            "base_url": "https://example.atlassian.net",
            "email": "security@example.com",
            "project_key": "SEC",
            "issue_type": "Task",
            "events": ["finding.workflow_changed"],
        },
        secret_configured=True,
    )
    save_integration(
        db,
        channel="JIRA",
        enabled=True,
        config=config,
        secret_ciphertext=encrypt_secret({"api_token": "jira-token"}, master_key=MASTER),
        actor="admin",
    )
    queue_jira_issue_create(db, finding_id="F-COLLAB", actor="operator")
    calls = []

    class Response:
        status_code = 201
        content = b'{"key":"SEC-101"}'
        headers = {}
        text = '{"key":"SEC-101"}'
        def json(self):
            return {"key": "SEC-101"}

    def fake_request(method, url, **kwargs):
        assert method == "POST"
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("app.services.collaboration.request_outbound", fake_request)
    first = deliver_collaboration_events(db, master_key=MASTER, due_soon_days=0)
    assert first["delivered"] == 1
    link = get_finding_external_link(db, "F-COLLAB")
    assert link and link["external_key"] == "SEC-101"
    assert calls[0][0].endswith("/rest/api/3/issue")

    queue_event_for_integrations(
        db,
        event_type="finding.workflow_changed",
        payload={"finding_id": "F-COLLAB", "status": "MITIGATED"},
        actor="operator",
    )
    second = deliver_collaboration_events(db, master_key=MASTER, due_soon_days=0)
    assert second["delivered"] == 1
    assert calls[-1][0].endswith("/rest/api/3/issue/SEC-101/comment")


def test_due_reminders_are_deduplicated_per_day(tmp_path: Path):
    db = _db(tmp_path)
    save_integration(
        db,
        channel="EMAIL",
        enabled=True,
        config={"events": ["finding.due_soon", "finding.overdue"]},
        secret_ciphertext="",
        actor="admin",
    )
    enqueue_due_reminders(db, due_soon_days=30)
    enqueue_due_reminders(db, due_soon_days=30)
    reminders = [item for item in list_collaboration_events(db) if item["event_type"].startswith("finding.")]
    assert len(reminders) == 1


def test_failed_jira_create_can_be_requeued_after_configuration_fix(tmp_path: Path):
    db = _db(tmp_path)
    save_integration(
        db,
        channel="JIRA",
        enabled=True,
        config={"events": ["finding.workflow_changed"]},
        secret_ciphertext=encrypt_secret({"api_token": "jira-secret"}, master_key=MASTER),
        actor="admin",
    )
    event_id = queue_jira_issue_create(db, finding_id="F-COLLAB", actor="operator")
    failed = record_collaboration_delivery(
        db, event_id=event_id, delivered=False, error="bad configuration",
        max_attempts=1, retryable=False,
    )
    assert failed["status"] == "FAILED"
    assert queue_jira_issue_create(db, finding_id="F-COLLAB", actor="operator") == event_id
    refreshed = next(item for item in list_collaboration_events(db) if item["event_id"] == event_id)
    assert refreshed["status"] == "PENDING"
    assert refreshed["attempts"] == 0


def test_delivery_record_lookup_is_not_limited_by_recent_event_window(tmp_path: Path):
    db = _db(tmp_path)
    now = "2026-08-02T00:00:00+00:00"
    rows = [
        (
            f"COL-{index:020d}", "EMAIL", "finding.workflow_changed", "F-COLLAB", "{}",
            "PENDING", 0, now, "", "test", f"2026-08-02T00:{index // 60:02d}:{index % 60:02d}+00:00",
        )
        for index in range(2001)
    ]
    with sqlite3.connect(db) as conn:
        conn.executemany(
            """INSERT INTO collaboration_events(
                   event_id,channel,event_type,finding_id,payload_json,status,attempts,
                   next_attempt_at,dedupe_key,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
    oldest = rows[0][0]
    updated = record_collaboration_delivery(db, event_id=oldest, delivered=True)
    assert updated["event_id"] == oldest
    assert updated["status"] == "DELIVERED"
