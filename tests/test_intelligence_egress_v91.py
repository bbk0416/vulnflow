from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
from typing import Iterator

import pytest

from app.services import intel
from app.services.osv import OsvError, query_components


@pytest.fixture()
def intelligence_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, int]]:
    record = {
        "id": "GHSA-test-0000-0001",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-9999"],
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib callback name
            if self.path == "/kev":
                body = json.dumps({
                    "vulnerabilities": [{"cveID": "CVE-2026-9999"}]
                }).encode()
            elif self.path.startswith("/epss?"):
                body = json.dumps({
                    "data": [{
                        "cve": "CVE-2026-9999",
                        "epss": "0.75",
                        "percentile": "0.95",
                    }]
                }).encode()
            elif self.path == "/v1/vulns/GHSA-test-0000-0001":
                body = json.dumps(record).encode()
            elif self.path == "/large":
                body = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-9999"}]})
                body = (body + (" " * 8192)).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802 - stdlib callback name
            if self.path != "/v1/querybatch":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
            body = json.dumps({
                "results": [
                    {"vulns": [{"id": record["id"], "modified": record["modified"]}]}
                    for _ in payload.get("queries", [])
                ]
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, requested_port, *args, **kwargs):
        if host in {"intel.example.test", "osv.example.test"}:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))
            ]
        return real_getaddrinfo(host, requested_port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    try:
        yield "intel.example.test", port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_intelligence_private_destination_is_blocked_by_default(
    monkeypatch: pytest.MonkeyPatch,
    intelligence_server: tuple[str, int],
) -> None:
    host, port = intelligence_server
    monkeypatch.setattr(intel, "KEV_URL", f"http://{host}:{port}/kev")
    with pytest.raises(intel.IntelligenceError, match="blocked network"):
        intel.fetch_kev_catalog(retries=1)


def test_intelligence_uses_pinned_transport_when_explicitly_allowed(
    monkeypatch: pytest.MonkeyPatch,
    intelligence_server: tuple[str, int],
) -> None:
    host, port = intelligence_server
    monkeypatch.setattr(intel, "KEV_URL", f"http://{host}:{port}/kev")
    monkeypatch.setattr(intel, "EPSS_URL", f"http://{host}:{port}/epss")
    catalog = intel.fetch_kev_catalog(
        retries=1,
        allow_private_networks=True,
        host_allowlist=host,
    )
    epss = intel.fetch_epss(
        ["CVE-2026-9999"],
        retries=1,
        allow_private_networks=True,
        host_allowlist=host,
    )
    assert catalog == {"CVE-2026-9999"}
    assert epss["CVE-2026-9999"] == {"epss": 0.75, "percentile": 0.95}


def test_intelligence_response_size_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    intelligence_server: tuple[str, int],
) -> None:
    host, port = intelligence_server
    monkeypatch.setattr(intel, "KEV_URL", f"http://{host}:{port}/large")
    with pytest.raises(intel.IntelligenceError, match="exceeded"):
        intel.fetch_kev_catalog(
            retries=1,
            max_response_bytes=4096,
            allow_private_networks=True,
            host_allowlist=host,
        )


def test_osv_private_destination_requires_explicit_policy(
    intelligence_server: tuple[str, int],
) -> None:
    _, port = intelligence_server
    component = {
        "component_id": "COMP-1",
        "purl": "pkg:pypi/example@1.0",
        "version": "1.0",
    }
    with pytest.raises(OsvError, match="blocked network"):
        query_components(
            [component],
            api_base=f"http://127.0.0.1:{port}",
            retries=1,
        )


def test_osv_uses_pinned_transport_and_response_limit(
    intelligence_server: tuple[str, int],
) -> None:
    _, port = intelligence_server
    component = {
        "component_id": "COMP-1",
        "purl": "pkg:pypi/example@1.0",
        "version": "1.0",
    }
    result = query_components(
        [component],
        api_base=f"http://127.0.0.1:{port}",
        retries=1,
        allow_private_networks=True,
        host_allowlist="127.0.0.1",
        max_response_bytes=4096,
    )
    assert result["component_vulnerability_ids"]["COMP-1"] == {
        "GHSA-test-0000-0001": "2026-01-01T00:00:00Z"
    }
    assert result["records"]["GHSA-test-0000-0001"]["aliases"] == ["CVE-2026-9999"]
