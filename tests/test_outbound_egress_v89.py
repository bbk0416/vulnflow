from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
from pathlib import Path

import pytest

from app.core.database_schema import init_db
from app.repositories.webhook_queue import list_webhook_events
from app.services.outbound_http import (
    OutboundPolicyError,
    OutboundResponseTooLarge,
    request_outbound,
    resolve_outbound_target,
)
from app.services.security_profile import evaluate_security_profile
from app.services.webhooks import (
    WebhookConfigError, deliver_due_events, parse_webhook_endpoints, queue_event,
)


PUBLIC_A = "93.184.216.34"
PUBLIC_B = "1.1.1.1"


def _answer(*addresses: str):
    return [
        (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443, 0, 0) if ":" in address else (address, 443))
        for address in addresses
    ]


def test_public_resolution_and_host_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _answer(PUBLIC_A, PUBLIC_B))
    target = resolve_outbound_target(
        "https://hooks.example.com/events?source=vulnflow",
        host_allowlist="*.example.com,api.example.net",
    )
    assert target.addresses == (PUBLIC_A, PUBLIC_B)
    assert target.path_and_query == "/events?source=vulnflow"
    assert target.host_header == "hooks.example.com"

    with pytest.raises(OutboundPolicyError, match="allowlisted"):
        resolve_outbound_target(
            "https://example.com/events", host_allowlist="*.example.com"
        )


def test_private_metadata_and_mixed_dns_are_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    for url in (
        "http://127.0.0.1:8000/private",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/private",
        "https://metadata.google.internal/computeMetadata/v1/",
    ):
        with pytest.raises(OutboundPolicyError):
            resolve_outbound_target(url)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: _answer(PUBLIC_A, "10.20.30.40"),
    )
    with pytest.raises(OutboundPolicyError, match="blocked network"):
        resolve_outbound_target("https://mixed.example.test/hook")


def test_validated_ip_is_pinned_and_host_header_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib callback name
            observed["host"] = str(self.headers.get("Host") or "")
            observed["path"] = self.path
            length = int(self.headers.get("Content-Length") or 0)
            observed["body"] = self.rfile.read(length).decode("utf-8")
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, *args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, requested_port, *args, **kwargs):
        if host == "hook.example.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))]
        return real_getaddrinfo(host, requested_port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    try:
        response = request_outbound(
            "POST",
            f"http://hook.example.test:{port}/events?id=7",
            body=b"payload",
            allow_private_networks=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    assert observed == {
        "host": f"hook.example.test:{port}",
        "path": "/events?id=7",
        "body": "payload",
    }


def test_response_size_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib callback name
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 8192)

        def log_message(self, *args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, requested_port, *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))
        ],
    )
    try:
        with pytest.raises(OutboundResponseTooLarge):
            request_outbound(
                "GET",
                f"http://large.example.test:{port}/",
                allow_private_networks=True,
                max_response_bytes=4096,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)



def test_webhook_configuration_rejects_credentials_and_empty_events() -> None:
    with pytest.raises(WebhookConfigError, match="사용자정보"):
        parse_webhook_endpoints(
            '{"ops":{"url":"https://user:password@hooks.example.com/events","secret":"0123456789abcdef","events":["*"]}}'
        )
    with pytest.raises(WebhookConfigError, match="하나 이상의"):
        parse_webhook_endpoints(
            '{"ops":{"url":"https://hooks.example.com/events","secret":"0123456789abcdef","events":[" "]}}'
        )

def test_webhook_private_destination_fails_without_network_access(tmp_path: Path) -> None:
    db = tmp_path / "webhooks.sqlite3"
    init_db(db)
    endpoints = parse_webhook_endpoints(
        '{"internal":{"url":"http://127.0.0.1:9/events","secret":"0123456789abcdef","events":["*"]}}',
        allow_insecure_http=True,
    )
    queue_event(
        db,
        endpoints=endpoints,
        event_type="finding.changed",
        payload={"finding_id": "F-1"},
        actor="test",
    )
    result = deliver_due_events(
        db,
        endpoints=endpoints,
        max_attempts=1,
        allow_private_networks=False,
    )
    assert result["failed"] == 1
    event = list_webhook_events(db, limit=10)[0]
    assert event["status"] == "FAILED"
    assert "blocked network" in event["last_error"]


def test_production_profile_rejects_private_egress_and_unlisted_webhooks(tmp_path: Path) -> None:
    values = {
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
        "OUTBOUND_ALLOW_PRIVATE_NETWORKS": True,
        "WEBHOOKS_JSON": '{"ops":{"url":"https://hooks.example.test","secret":"0123456789abcdef","events":["*"]}}',
        "OUTBOUND_HOST_ALLOWLIST": "",
    }
    report = evaluate_security_profile(values, tokens={})
    codes = {item.code for item in report.findings}
    assert {"outbound.private_networks", "outbound.allowlist"} <= codes
