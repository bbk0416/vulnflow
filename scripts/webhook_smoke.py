from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

SECRET = "local-webhook-smoke-secret-12345"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    captured: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            captured["body"] = body
            captured["signature"] = self.headers.get("X-VulnFlow-Signature")
            captured["event_id"] = self.headers.get("X-VulnFlow-Event-ID")
            captured["event_type"] = self.headers.get("X-VulnFlow-Event-Type")
            self.send_response(204)
            self.end_headers()

        def log_message(self, format, *args):
            return

    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow_webhook_") as temp_dir:
            os.environ["VULNFLOW_DB"] = str(Path(temp_dir) / "webhook.sqlite3")
            # Webhook 동작만 검증하는 시험이므로 클러스터 하트비트와 작업 워커를 끕니다.
            # 각 기능은 cluster_smoke.py와 job_worker_smoke.py에서 별도로 검증합니다.
            os.environ["VULNFLOW_CLUSTER_COORDINATION_ENABLED"] = "0"
            os.environ["VULNFLOW_JOB_WORKER_ENABLED"] = "0"
            os.environ["VULNFLOW_MAINTENANCE_INTERVAL_MINUTES"] = "0"
            os.environ["VULNFLOW_BACKUP_INTERVAL_HOURS"] = "0"
            os.environ["VULNFLOW_WEBHOOKS_JSON"] = json.dumps({
                "local": {
                    "url": f"http://127.0.0.1:{port}/hook",
                    "secret": SECRET,
                    "events": ["finding.workflow_changed"],
                }
            })
            os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"
            os.environ["VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK"] = "1"
            from app import main as app_main

            with TestClient(app_main.app) as client:
                page = client.get("/finding/F-0001")
                token = client.cookies.get(app_main.CSRF_COOKIE)
                finding = client.get("/api/v1/findings/F-0001").json()
                changed = client.post(
                    "/finding/F-0001",
                    data={
                        "csrf_token": token,
                        "status": "IN_PROGRESS",
                        "owner": "webhook-smoke",
                        "due_date": "",
                        "exception_expiry": "",
                        "risk_acceptance_reason": "",
                        "risk_acceptance_approver": "",
                        "notes": "local receiver test",
                        "row_version": str(finding["row_version"]),
                    },
                    follow_redirects=False,
                )
                if changed.status_code != 303:
                    raise SystemExit(f"workflow change failed: {changed.status_code}")
                delivered = client.post(
                    "/webhooks/deliver", data={"csrf_token": token}, follow_redirects=False
                )
                if delivered.status_code != 303:
                    raise SystemExit(f"webhook delivery failed: {delivered.status_code}")
                events = client.get("/api/v1/webhooks").json()["items"]
                if not events or events[0]["status"] != "DELIVERED":
                    raise SystemExit("webhook event was not delivered")

            body = captured.get("body")
            if not isinstance(body, bytes):
                raise SystemExit("receiver did not capture a body")
            expected = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
            if captured.get("signature") != expected:
                raise SystemExit("webhook signature mismatch")
            payload = json.loads(body)
            if payload.get("event_id") != captured.get("event_id"):
                raise SystemExit("event ID header/body mismatch")
            if captured.get("event_type") != "finding.workflow_changed":
                raise SystemExit("unexpected event type")
            print(f"receiver status: 204")
            print(f"event type: {captured['event_type']}")
            print(f"signature verified: yes")
            print("webhook smoke passed: 3 checks")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
