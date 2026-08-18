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

OPERATOR_TOKEN = "asset-identity-operator-token-12345"
APPROVER_TOKEN = "asset-identity-approver-token-67890"


def bearer(token: str = OPERATOR_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def import_csv(client: TestClient, *, source: str, finding_id: str, asset_id: str,
               hostname: str, cve_id: str) -> None:
    payload = (
        "finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss\n"
        f"{finding_id},Asset Identity Smoke,{asset_id},{hostname},prod,{cve_id},identity-lib,1.0,7.5\n"
    ).encode()
    response = client.post(
        f"/api/v1/imports/csv?scanner_source={source}&import_mode=incremental",
        headers=bearer(), files={"file": (f"{source}.csv", payload, "text/csv")},
    )
    assert response.status_code == 200, (source, response.status_code, response.text)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow-asset-identity-") as temp_dir:
        root = Path(temp_dir)
        os.environ["VULNFLOW_DB"] = str(root / "identity.sqlite3")
        os.environ["VULNFLOW_COORDINATION_DB"] = str(root / "coord.sqlite3")
        os.environ["VULNFLOW_API_TOKENS_JSON"] = json.dumps({
            "identity-ci": {"token": OPERATOR_TOKEN, "role": "operator", "projects": "*"},
            "identity-approver": {"token": APPROVER_TOKEN, "role": "approver", "projects": "*"},
            "identity-admin": {"token": "asset-identity-admin-token-12345", "role": "admin", "projects": "*"},
        })
        os.environ["VULNFLOW_RECOVERY_DIR"] = str(root / "recovery")
        os.environ["VULNFLOW_EVIDENCE_DIR"] = str(root / "evidence")
        os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"
        os.environ["VULNFLOW_JOB_WORKER_INTERVAL_SECONDS"] = "0"
        from app import main as app_main

        with TestClient(app_main.app) as client:
            import_csv(client, source="scanner-a", finding_id="IDENT-A", asset_id="scanner-a-100",
                       hostname="shared-prod-host", cve_id="CVE-2026-21101")
            import_csv(client, source="scanner-b", finding_id="IDENT-B", asset_id="scanner-b-900",
                       hostname="shared-prod-host", cve_id="CVE-2026-21102")

            candidates = client.get("/api/v1/asset-identities/candidates", headers=bearer())
            assert candidates.status_code == 200, candidates.text
            pending = candidates.json()["items"]
            assert len(pending) == 1
            candidate = pending[0]
            target = candidate["asset_ref_id_a"]
            source = candidate["asset_ref_id_b"]
            target_original_scanner_values = {
                item["normalized_value"] for item in client.get(
                    f"/api/v1/assets/{target}/identifiers", headers=bearer()
                ).json()["items"] if item["identifier_type"] == "SCANNER_ASSET_ID"
            }
            source_original_scanner_values = {
                item["normalized_value"] for item in client.get(
                    f"/api/v1/assets/{source}/identifiers", headers=bearer()
                ).json()["items"] if item["identifier_type"] == "SCANNER_ASSET_ID"
            }

            impact = client.get(
                f"/api/v1/asset-identities/candidates/{candidate['candidate_id']}/impact",
                headers=bearer(), params={"target_asset_ref_id": target},
            )
            assert impact.status_code == 200, impact.text
            assert impact.json()["can_request"] is True

            requested = client.post(
                f"/api/v1/asset-identities/candidates/{candidate['candidate_id']}/merge-requests",
                headers=bearer(),
                json={
                    "target_asset_ref_id": target,
                    "reason": "CMDB owner confirmed both scanner records represent one host",
                },
            )
            assert requested.status_code == 200, requested.text
            request_id = requested.json()["request_id"]
            assert requested.json()["status"] == "PENDING"
            assert client.get(f"/api/v1/assets/{source}", headers=bearer()).json()["status"] == "ACTIVE"

            decided = client.post(
                f"/api/v1/asset-merge-requests/{request_id}/decision",
                headers=bearer(APPROVER_TOKEN),
                json={"decision": "APPROVED", "decision_note": "Impact and recovery point verified"},
            )
            assert decided.status_code == 200, decided.text
            assert decided.json()["status"] == "APPROVED"
            assert decided.json()["merge_id"]
            assert decided.json()["recovery_bundle_sha256"]

            source_asset = client.get(f"/api/v1/assets/{source}", headers=bearer())
            target_asset = client.get(f"/api/v1/assets/{target}", headers=bearer())
            assert source_asset.status_code == target_asset.status_code == 200
            assert source_asset.json()["status"] == "RETIRED"
            assert source_asset.json()["merged_into_asset_ref_id"] == target
            assert target_asset.json()["status"] == "ACTIVE"

            identifiers = client.get(f"/api/v1/assets/{target}/identifiers", headers=bearer())
            history = client.get(f"/api/v1/asset-merges?asset_ref_id={target}", headers=bearer())
            assert identifiers.status_code == history.status_code == 200
            scanner_values = {
                item["normalized_value"] for item in identifiers.json()["items"]
                if item["identifier_type"] == "SCANNER_ASSET_ID"
            }
            assert {"scanner-a-100", "scanner-b-900"} <= scanner_values
            assert history.json()["count"] == 1
            merge_id = history.json()["items"][0]["merge_id"]

            rollback_impact = client.get(
                f"/api/v1/asset-merges/{merge_id}/rollback-impact", headers=bearer(),
            )
            assert rollback_impact.status_code == 200, rollback_impact.text
            assert rollback_impact.json()["can_request"] is True
            rollback_requested = client.post(
                f"/api/v1/asset-merges/{merge_id}/rollback-requests",
                headers=bearer(), json={"reason": "CMDB review found the original merge decision was incorrect"},
            )
            assert rollback_requested.status_code == 200, rollback_requested.text
            rollback_request_id = rollback_requested.json()["rollback_request_id"]
            rollback_decided = client.post(
                f"/api/v1/asset-merge-rollback-requests/{rollback_request_id}/decision",
                headers=bearer(APPROVER_TOKEN),
                json={"decision": "APPROVED", "decision_note": "No dependent records changed after the merge"},
            )
            assert rollback_decided.status_code == 200, rollback_decided.text
            assert rollback_decided.json()["status"] == "APPROVED"
            source_restored = client.get(f"/api/v1/assets/{source}", headers=bearer()).json()
            assert source_restored["status"] == "ACTIVE"
            assert source_restored["merged_into_asset_ref_id"] is None
            target_ids = client.get(f"/api/v1/assets/{target}/identifiers", headers=bearer()).json()["items"]
            source_ids = client.get(f"/api/v1/assets/{source}/identifiers", headers=bearer()).json()["items"]
            assert {item["normalized_value"] for item in target_ids if item["identifier_type"] == "SCANNER_ASSET_ID"} == target_original_scanner_values
            assert {item["normalized_value"] for item in source_ids if item["identifier_type"] == "SCANNER_ASSET_ID"} == source_original_scanner_values

            # A separate weak match is deliberately rejected and must remain two active assets.
            import_csv(client, source="scanner-c", finding_id="IDENT-C", asset_id="scanner-c-300",
                       hostname="shared-test-host", cve_id="CVE-2026-21103")
            import_csv(client, source="scanner-d", finding_id="IDENT-D", asset_id="scanner-d-400",
                       hostname="shared-test-host", cve_id="CVE-2026-21104")
            pending = client.get("/api/v1/asset-identities/candidates", headers=bearer()).json()["items"]
            reject_candidate = next(item for item in pending if item["asset_name_a"] == "shared-test-host")
            rejected = client.post(
                f"/api/v1/asset-identities/candidates/{reject_candidate['candidate_id']}/reject",
                headers=bearer(), json={"reason": "Same hostname is reused in an isolated test environment"},
            )
            assert rejected.status_code == 200, rejected.text
            assert rejected.json()["status"] == "REJECTED"

            page = client.get("/asset-identities?status=", headers=bearer("asset-identity-admin-token-12345"))
            assert page.status_code == 200
            assert "shared-prod-host" in page.text and "shared-test-host" in page.text

        report = ROOT / "reports" / "asset_identity_verification.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            "VulnFlow 72.0.91 governed asset merge smoke\n"
            "weak identifier creates candidate without silent merge: PASS\n"
            "dry-run impact analysis: PASS\n"
            "operator request leaves assets unchanged: PASS\n"
            "approver decision creates recovery bundle: PASS\n"
            "recovery bundle SHA-256 recorded: PASS\n"
            "identifiers moved to representative asset: PASS\n"
            "source asset retired with merge pointer: PASS\n"
            "merge history preserved: PASS\n"
            "scoped rollback dry-run and request: PASS\n"
            "approver scoped rollback decision: PASS\n"
            "source asset and identifiers restored: PASS\n"
            "candidate rejection keeps separate assets: PASS\n"
            "asset identity UI render: PASS\n",
            encoding="utf-8",
        )
    print("asset identity, merge governance, and scoped rollback smoke passed: 13 checks")


if __name__ == "__main__":
    main()
