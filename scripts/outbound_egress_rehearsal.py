from __future__ import annotations

"""Exercise pinned HTTPS egress, hostname validation, and proxy independence."""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.outbound_http import (  # noqa: E402
    OutboundPolicyError,
    request_outbound,
)


def _certificate(directory: Path) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl is required for the live outbound TLS rehearsal")
    key = directory / "server.key"
    cert = directory / "server.crt"
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=hook.example.test",
            "-addext", "subjectAltName=DNS:hook.example.test",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def run_rehearsal() -> dict[str, Any]:
    observed: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib callback name
            length = int(self.headers.get("Content-Length") or 0)
            observed.update({
                "host": self.headers.get("Host"),
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "payload": self.rfile.read(length).decode("utf-8"),
            })
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, *args):
            return None

    with tempfile.TemporaryDirectory(prefix="vulnflow-outbound-") as raw:
        work = Path(raw)
        cert, key = _certificate(work)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)

        def sni_callback(_socket, server_name, _context):
            observed["sni"] = server_name

        server_context.set_servername_callback(sni_callback)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])

        client_context = ssl.create_default_context(cafile=str(cert))
        real_getaddrinfo = socket.getaddrinfo

        def pinned_dns(host, requested_port, *args, **kwargs):
            if host == "hook.example.test":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))
                ]
            return real_getaddrinfo(host, requested_port, *args, **kwargs)

        socket.getaddrinfo = pinned_dns
        previous_proxy = os.environ.get("HTTPS_PROXY")
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
        try:
            response = request_outbound(
                "POST",
                f"https://hook.example.test:{port}/events?run=1",
                json_body={"finding_id": "F-OUTBOUND"},
                basic_auth=("vulnflow", "secret"),
                allow_private_networks=True,
                host_allowlist="*.example.test",
                ssl_context=client_context,
            )
            private_blocked = False
            try:
                request_outbound(
                    "POST",
                    f"https://hook.example.test:{port}/events",
                    ssl_context=client_context,
                )
            except OutboundPolicyError:
                private_blocked = True
            allowlist_blocked = False
            try:
                request_outbound(
                    "POST",
                    f"https://hook.example.test:{port}/events",
                    allow_private_networks=True,
                    host_allowlist="api.example.test",
                    ssl_context=client_context,
                )
            except OutboundPolicyError:
                allowlist_blocked = True
        finally:
            socket.getaddrinfo = real_getaddrinfo
            if previous_proxy is None:
                os.environ.pop("HTTPS_PROXY", None)
            else:
                os.environ["HTTPS_PROXY"] = previous_proxy
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    expected_auth = "Basic " + base64.b64encode(b"vulnflow:secret").decode("ascii")
    checks = {
        "https_status": response.status_code == 201,
        "response_json": response.json() == {"accepted": True},
        "tls_sni_original_hostname": observed.get("sni") == "hook.example.test",
        "host_header_original_hostname": observed.get("host") == f"hook.example.test:{port}",
        "path_and_query_preserved": observed.get("path") == "/events?run=1",
        "basic_auth_preserved": observed.get("authorization") == expected_auth,
        "environment_proxy_ignored": response.status_code == 201,
        "private_network_default_blocked": private_blocked,
        "hostname_allowlist_enforced": allowlist_blocked,
    }
    return {
        "format": "vulnflow-outbound-egress-rehearsal/1",
        "passed": all(checks.values()),
        "checks": checks,
        "observed": {key: value for key, value in observed.items() if key != "authorization"},
        "limitations": [
            "The rehearsal uses a temporary local CA and loopback server, not a customer endpoint.",
            "SMTP uses a separate pinned transport and STARTTLS rehearsal in VulnFlow 72.0.31.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    report = run_rehearsal()
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(payload)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
