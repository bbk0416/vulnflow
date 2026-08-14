from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_reconciliation_") as temp_dir:
        os.environ["VULNFLOW_DB"] = str(Path(temp_dir) / "reconciliation.sqlite3")
        os.environ["VULNFLOW_COORDINATION_DB"] = str(Path(temp_dir) / "coord.sqlite3")
        os.environ["VULNFLOW_API_TOKENS_JSON"] = json.dumps({
            "scanner-ci": {"token": "reconciliation-operator-token-12345", "role": "operator", "projects": "*"},
            "admin-ci": {"token": "reconciliation-admin-token-1234567", "role": "admin", "projects": "*"}
        })
        os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"
        os.environ["VULNFLOW_JOB_WORKER_INTERVAL_SECONDS"] = "0"
        from app import main as app_main

        with TestClient(app_main.app) as client:
            admin = {"Authorization": "Bearer reconciliation-admin-token-1234567"}
            csrf = client.get("/", headers=admin).cookies.get(app_main.CSRF_COOKIE) or client.cookies.get(app_main.CSRF_COOKIE)
            a = (
                b"finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss,patch_available\n"
                b"A-20,Reconciliation Demo,ASSET-R20,demo.example.com,prod,CVE-2026-20020,demo-lib,1.0,7.5,0\n"
            )
            b = (
                b"finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss,patch_available\n"
                b"B-20,Reconciliation Demo,ASSET-R20,demo.example.com,prod,CVE-2026-20020,demo-lib,1.1,9.1,1\n"
            )
            for source, payload in (("scanner-a", a), ("scanner-b", b)):
                response = client.post(
                    "/upload/findings",
                    data={"csrf_token": csrf, "scanner_source": source, "import_mode": "snapshot"},
                    files={"file": (f"{source}.csv", payload, "text/csv")},
                    follow_redirects=False, headers=admin,
                )
                assert response.status_code == 303, (source, response.status_code, response.text)

            detail = client.get("/api/v1/findings/A-20/sources", headers=admin)
            assert detail.status_code == 200
            body = detail.json()
            assert len(body["records"]) == 2
            assert body["unresolved_count"] >= 3
            scanner_a = next(item for item in body["records"] if item["scanner_source"] == "scanner-a")

            headers = {"Authorization": "Bearer reconciliation-operator-token-12345"}
            resolved = client.post(
                "/api/v1/findings/A-20/source-resolution",
                headers=headers,
                json={
                    "field_name": "cvss",
                    "chosen_source_record_id": scanner_a["source_record_id"],
                    "reason": "authenticated scanner selected for smoke verification",
                },
            )
            assert resolved.status_code == 200, resolved.text
            finding = client.get("/api/v1/findings/A-20", headers=admin).json()
            assert finding["cvss"] == 7.5
            assert finding["source_count"] == 2

            empty = b"finding_id,product,cve_id\n"
            missing_a = client.post(
                "/upload/findings",
                data={"csrf_token": csrf, "scanner_source": "scanner-a", "import_mode": "snapshot"},
                files={"file": ("empty-a.csv", empty, "text/csv")},
                follow_redirects=False, headers=admin,
            )
            assert missing_a.status_code == 303
            assert client.get("/api/v1/findings/A-20", headers=admin).json()["record_state"] == "ACTIVE"
            missing_b = client.post(
                "/upload/findings",
                data={"csrf_token": csrf, "scanner_source": "scanner-b", "import_mode": "snapshot"},
                files={"file": ("empty-b.csv", empty, "text/csv")},
                follow_redirects=False, headers=admin,
            )
            assert missing_b.status_code == 303
            assert client.get("/api/v1/findings/A-20", headers=admin).json()["record_state"] == "STALE"

        report = ROOT / "reports" / "reconciliation_verification.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            "VulnFlow 72.0.87 multi-scanner reconciliation smoke\n"
            "two sources merged: PASS\n"
            "source conflict exposed: PASS\n"
            "authoritative source decision: PASS\n"
            "single source absence keeps ACTIVE: PASS\n"
            "all source absence marks STALE: PASS\n",
            encoding="utf-8",
        )
    print("reconciliation smoke passed: 5 checks")


if __name__ == "__main__":
    main()
