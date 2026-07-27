from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "2025-01-01T00:00:00Z",
    "published": "2021-12-10T00:00:00Z",
    "summary": "Log4Shell remote code execution",
    "details": "Local HTTP OSV smoke fixture",
    "aliases": ["CVE-2021-44228"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.0"}]}],
        "ecosystem_specific": {"severity": "CRITICAL"},
    }],
}


class OsvHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/querybatch":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        body = json.dumps({
            "results": [
                {"vulns": [{"id": RECORD["id"], "modified": RECORD["modified"]}]}
                for _ in payload.get("queries", [])
            ]
        }).encode()
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


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), OsvHandler)
    # Do not let an HTTP keep-alive request thread delay process teardown after
    # the smoke assertions have already completed.
    server.daemon_threads = True
    server.block_on_close = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow-osv-http-") as temp:
            root = Path(temp)
            os.environ["VULNFLOW_DB"] = str(root / "vulnflow.sqlite3")
            os.environ["VULNFLOW_COORDINATION_DB"] = str(root / "coordination.sqlite3")
            os.environ["VULNFLOW_EVIDENCE_DIR"] = str(root / "evidence")
            os.environ["VULNFLOW_RECOVERY_DIR"] = str(root / "recovery")
            os.environ["VULNFLOW_JOB_WORKER_ENABLED"] = "0"
            os.environ["VULNFLOW_API_TOKENS_JSON"] = json.dumps({
                "operator": {"token": "osv-http-operator-token-12345", "role": "operator"},
            })
            os.environ["VULNFLOW_USERS_JSON"] = json.dumps({
                "admin": {"password": "osv-http-admin-pass", "role": "admin"},
            })
            os.environ["VULNFLOW_OSV_API_BASE"] = f"http://127.0.0.1:{server.server_address[1]}"
            os.environ["VULNFLOW_OSV_RETRIES"] = "1"
            os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"

            from app import main as app_main
            from app.core.storage import claim_background_job, complete_background_job, get_background_job

            token = bearer("osv-http-operator-token-12345")
            with TestClient(app_main.app) as client:
                sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "metadata": {"component": {"type": "application", "name": "Portal", "version": "1.0"}},
                    "components": [{
                        "type": "library",
                        "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    }],
                }
                created = client.post(
                    "/api/v1/sboms",
                    headers=token,
                    data={"notes": "OSV HTTP smoke"},
                    files={"file": ("portal.cdx.json", json.dumps(sbom).encode(), "application/json")},
                )
                assert created.status_code == 200, created.text
                sbom_id = created.json()["sbom_id"]

                queued = client.post(f"/api/v1/sboms/{sbom_id}/osv-scan", headers=token)
                assert queued.status_code == 200, queued.text
                job_id = queued.json()["job_id"]

                claimed = claim_background_job(
                    app_main.DB_PATH,
                    worker_id="osv-http-worker",
                    lease_seconds=60,
                    allowed_types=["OSV_SCAN"],
                )
                assert claimed and claimed["job_id"] == job_id
                result = app_main._execute_background_job(claimed, worker_id="osv-http-worker")
                complete_background_job(
                    app_main.DB_PATH,
                    job_id=job_id,
                    worker_id="osv-http-worker",
                    result=result,
                )
                assert get_background_job(app_main.DB_PATH, job_id)["status"] == "SUCCEEDED"

                scans = client.get(f"/api/v1/sboms/{sbom_id}/osv-scans", headers=token)
                matches = client.get(f"/api/v1/sboms/{sbom_id}/osv-matches", headers=token)
                assert scans.status_code == 200 and len(scans.json()["items"]) == 1
                assert matches.status_code == 200 and len(matches.json()["items"]) == 1
                match_id = matches.json()["items"][0]["match_id"]

                confirmed = client.post(
                    f"/api/v1/osv-matches/{match_id}/decision",
                    headers=token,
                    json={"decision": "CONFIRM", "reason": "HTTP smoke reviewed"},
                )
                assert confirmed.status_code == 200, confirmed.text
                finding_id = confirmed.json()["finding_id"]
                finding = client.get(f"/api/v1/findings/{finding_id}", headers=token)
                assert finding.status_code == 200
                assert finding.json()["cve_id"] == "CVE-2021-44228"
                print(
                    "OSV HTTP smoke passed: "
                    "SBOM=1 queued=1 scan=1 candidate=1 confirmed=1 finding=CVE-2021-44228"
                )
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
