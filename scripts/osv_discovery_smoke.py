from __future__ import annotations

import io
import json
import tempfile
import threading
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import init_db, list_findings
from app.services.sbom import (
    decide_osv_match,
    list_osv_matches,
    parse_cyclonedx_json,
    run_osv_scan,
    store_cyclonedx_document,
)

RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "2025-01-01T00:00:00Z",
    "published": "2021-12-10T00:00:00Z",
    "summary": "Log4Shell remote code execution",
    "details": "Local OSV smoke fixture",
    "aliases": ["CVE-2021-44228"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.0"}]}],
        "ecosystem_specific": {"severity": "CRITICAL"},
    }],
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/querybatch":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        response = {"results": [{"vulns": [{"id": RECORD["id"], "modified": RECORD["modified"]}]} for _ in payload.get("queries", [])]}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/v1/vulns/GHSA-jfh8-c2jp-5v3q":
            self.send_error(404)
            return
        body = json.dumps(RECORD).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow-osv-smoke-") as temp:
            db = Path(temp) / "vulnflow.db"
            init_db(db)
            payload = {
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"type": "application", "name": "Portal", "version": "1.0"}},
                "components": [{
                    "type": "library", "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    "name": "log4j-core", "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                }],
            }
            parsed = parse_cyclonedx_json(io.BytesIO(json.dumps(payload).encode()))
            doc = store_cyclonedx_document(str(db), parsed, source_filename="portal.cdx.json", actor="smoke")
            base = f"http://127.0.0.1:{server.server_address[1]}"
            first = run_osv_scan(str(db), doc["sbom_id"], actor="operator", api_base=base, source_job_id="JOB-SMOKE-1", allow_private_networks=True, host_allowlist="127.0.0.1")
            second = run_osv_scan(str(db), doc["sbom_id"], actor="operator", api_base=base, source_job_id="JOB-SMOKE-2", allow_private_networks=True, host_allowlist="127.0.0.1")
            matches = list_osv_matches(str(db), sbom_id=doc["sbom_id"])
            confirmed = decide_osv_match(str(db), matches[0]["match_id"], decision="CONFIRM", reason="smoke", actor="operator")
            finding = next(row for row in list_findings(db) if row["finding_id"] == confirmed["finding_id"])
            assert first["new_candidates"] == 1
            assert second["cache_hits"] == 1
            assert finding["cve_id"] == "CVE-2021-44228"
            print("OSV discovery smoke passed: candidate=1 cache_hit=1 finding=CVE-2021-44228")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
