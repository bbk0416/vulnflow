from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

TOKENS = json.dumps({
    "scanner": {"token": "scanner-smoke-token-123456", "role": "operator", "projects": "*"},
    "approval": {"token": "approval-smoke-token-12345", "role": "approver", "projects": "*"},
    "admin-api": {"token": "admin-smoke-token-1234567", "role": "admin", "projects": "*"},
})
WEBHOOKS = json.dumps({
    "smoke": {"url": "http://127.0.0.1:9/vulnflow", "secret": "smoke-webhook-secret-12345", "events": ["*"]}
})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_smoke_") as temp_dir:
        os.environ["VULNFLOW_DB"] = str(Path(temp_dir) / "smoke.sqlite3")
        os.environ["VULNFLOW_EVIDENCE_DIR"] = str(Path(temp_dir) / "evidence")
        os.environ["VULNFLOW_RECOVERY_DIR"] = str(Path(temp_dir) / "recovery")
        os.environ["VULNFLOW_EXPORT_DIR"] = str(Path(temp_dir) / "exports")
        os.environ["VULNFLOW_EXPORT_RETENTION_DAYS"] = "2"
        os.environ["VULNFLOW_EXPORT_QUOTA_MB"] = "64"
        os.environ["VULNFLOW_EXPORT_MIN_FREE_MB"] = "0"
        os.environ["VULNFLOW_JOB_WORKER_INTERVAL_SECONDS"] = "1"
        os.environ["VULNFLOW_API_TOKENS_JSON"] = TOKENS
        os.environ["VULNFLOW_WEBHOOKS_JSON"] = WEBHOOKS
        os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"
        os.environ["VULNFLOW_SIGNING_KEYS_JSON"] = json.dumps({
            "audit-http-v1": "http-smoke-audit-signing-key-v1",
            "backup-http-v1": "http-smoke-backup-signing-key-v1",
        })
        os.environ["VULNFLOW_AUDIT_ACTIVE_KEY_ID"] = "audit-http-v1"
        os.environ["VULNFLOW_BACKUP_ACTIVE_KEY_ID"] = "backup-http-v1"
        os.environ["VULNFLOW_BACKUP_REQUIRE_SIGNATURE"] = "1"
        os.environ["VULNFLOW_AUDIT_REQUIRE_SIGNATURE"] = "1"
        from app import main as app_main

        checks: list[tuple[str, int]] = []
        admin = bearer("admin-smoke-token-1234567")
        with TestClient(app_main.app) as client:
            for path in [
                "/", "/assets", "/asset-identities", "/sboms", "/exposure-groups", "/campaigns", "/upload", "/imports", "/reconciliation", "/jobs", "/execution-receipts", "/exports", "/pilot", "/audit", "/approvals", "/verifications", "/config-changes", "/maintenance", "/webhooks", "/system", "/cluster",
                "/api/v1/summary", "/api/v1/assets?limit=5", "/api/v1/sboms", "/api/v1/exposure-groups?limit=5", "/api/v1/campaigns?limit=5", "/api/v1/findings?limit=5", "/api/v1/audit?limit=5",
                "/api/v1/imports?limit=5", "/api/v1/jobs?limit=5", "/api/v1/exports?limit=5", "/api/v1/approvals?limit=5", "/api/v1/verifications",
                "/api/v1/maintenance-runs?limit=5", "/api/v1/webhooks?limit=5", "/api/v1/pilot-readiness",
                "/policies", "/api/v1/policies",
                "/metrics", "/docs", "/openapi.json",
                "/export/findings.csv", "/export/assets.csv", "/export/campaigns.csv", "/export/audit.csv", "/export/report.html", "/export/backup.sqlite3",
                "/export/config-audit.json", "/export/audit-integrity.json", "/export/recovery-bundle.zip", "/export/executive-report.html",
            ]:
                response = client.get(path, headers=admin)
                checks.append((path, response.status_code))
                if response.status_code != 200:
                    raise SystemExit(f"HTTP smoke failed: {path} -> {response.status_code}")

            receipt_api = client.get(
                "/api/v1/execution-receipts?limit=5", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/execution-receipts", receipt_api.status_code))
            if receipt_api.status_code != 200 or "summary" not in receipt_api.json():
                raise SystemExit(f"HTTP smoke failed: execution receipts -> {receipt_api.status_code} {receipt_api.text}")

            page_one = client.get("/api/v1/findings?record_state=ALL&limit=2&page=1", headers=admin)
            page_two = client.get("/api/v1/findings?record_state=ALL&limit=2&page=2", headers=admin)
            checks.extend([
                ("GET /api/v1/findings page=1", page_one.status_code),
                ("GET /api/v1/findings page=2", page_two.status_code),
            ])
            if page_one.status_code != 200 or page_two.status_code != 200:
                raise SystemExit("HTTP smoke failed: paginated findings API")
            one = page_one.json(); two = page_two.json()
            required_page_fields = {"count", "items", "page", "page_size", "total_pages", "query_ms"}
            if not required_page_fields <= set(one):
                raise SystemExit("HTTP smoke failed: pagination metadata missing")
            if {item["finding_id"] for item in one["items"]} & {item["finding_id"] for item in two["items"]}:
                raise SystemExit("HTTP smoke failed: adjacent finding pages overlap")

            checkpoint = client.post(
                "/api/v1/audit/checkpoints", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("POST /api/v1/audit/checkpoints", checkpoint.status_code))
            if (checkpoint.status_code != 200 or not checkpoint.json().get("signed")
                    or checkpoint.json().get("key_id") != "audit-http-v1"):
                raise SystemExit(f"HTTP smoke failed: audit checkpoint -> {checkpoint.status_code} {checkpoint.text}")
            audit_integrity = client.get(
                "/api/v1/audit/integrity", headers=bearer("approval-smoke-token-12345")
            )
            checks.append(("GET /api/v1/audit/integrity", audit_integrity.status_code))
            if audit_integrity.status_code != 200 or not audit_integrity.json().get("valid"):
                raise SystemExit(f"HTTP smoke failed: audit integrity -> {audit_integrity.status_code} {audit_integrity.text}")

            proof_created = client.post(
                "/api/v1/audit/proofs", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("POST /api/v1/audit/proofs", proof_created.status_code))
            if proof_created.status_code != 200 or proof_created.json().get("export_type") != "INTEGRITY_PROOF_ZIP":
                raise SystemExit(f"HTTP smoke failed: integrity proof create -> {proof_created.status_code} {proof_created.text}")
            proof_artifact_id = proof_created.json()["artifact_id"]
            proof_verified = client.get(
                f"/api/v1/audit/proofs/{proof_artifact_id}/verify",
                headers=bearer("approval-smoke-token-12345"),
            )
            checks.append(("GET /api/v1/audit/proofs/{artifact_id}/verify", proof_verified.status_code))
            if proof_verified.status_code != 200 or not proof_verified.json().get("valid"):
                raise SystemExit(f"HTTP smoke failed: integrity proof verify -> {proof_verified.status_code} {proof_verified.text}")
            proof_download = client.get(f"/exports/{proof_artifact_id}/download", headers=admin)
            checks.append(("GET /exports/{proof_artifact_id}/download", proof_download.status_code))
            if proof_download.status_code != 200 or "application/zip" not in proof_download.headers.get("content-type", ""):
                raise SystemExit(f"HTTP smoke failed: integrity proof download -> {proof_download.status_code}")

            recovery_bundle = client.get("/export/recovery-bundle.zip", headers=admin)
            validated = client.post(
                "/api/v1/recovery/validate",
                headers=bearer("admin-smoke-token-1234567"),
                files={"file": ("recovery.zip", recovery_bundle.content, "application/zip")},
            )
            checks.append(("POST /api/v1/recovery/validate", validated.status_code))
            if (validated.status_code != 200 or not validated.json().get("valid")
                    or validated.json().get("signing_key_id") != "backup-http-v1"):
                raise SystemExit(f"HTTP smoke failed: recovery validate -> {validated.status_code} {validated.text}")
            config_audit = client.get(
                "/api/v1/system/config-audit", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/config-audit", config_audit.status_code))
            if config_audit.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: config audit -> {config_audit.status_code}")
            config_baseline = client.post(
                "/api/v1/system/config-baseline",
                headers=bearer("admin-smoke-token-1234567"),
                json={"note": "HTTP smoke approved baseline"},
            )
            checks.append(("POST /api/v1/system/config-baseline", config_baseline.status_code))
            if config_baseline.status_code != 200 or config_baseline.json().get("status") != "ACTIVE":
                raise SystemExit(f"HTTP smoke failed: config baseline -> {config_baseline.status_code} {config_baseline.text}")
            config_drift = client.get(
                "/api/v1/system/config-drift", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/config-drift", config_drift.status_code))
            if config_drift.status_code != 200 or config_drift.json().get("current", {}).get("status") != "IN_SYNC":
                raise SystemExit(f"HTTP smoke failed: config drift -> {config_drift.status_code} {config_drift.text}")
            config_check = client.post(
                "/api/v1/system/config-drift/check", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("POST /api/v1/system/config-drift/check", config_check.status_code))
            if config_check.status_code != 200 or config_check.json().get("status") != "IN_SYNC":
                raise SystemExit(f"HTTP smoke failed: config drift check -> {config_check.status_code} {config_check.text}")
            os.environ["VULNFLOW_COOKIE_SECURE"] = "1"
            now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0)
            config_change = client.post(
                "/api/v1/system/config-changes",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "title": "HTTP smoke secure cookie", "reason": "TLS rollout",
                    "rollback_plan": "restore VULNFLOW_COOKIE_SECURE=0 and restart",
                    "window_start": (now - __import__("datetime").timedelta(minutes=5)).isoformat(),
                    "window_end": (now + __import__("datetime").timedelta(hours=2)).isoformat(),
                },
            )
            checks.append(("POST /api/v1/system/config-changes", config_change.status_code))
            if config_change.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: config change request -> {config_change.status_code} {config_change.text}")
            config_change_id = config_change.json()["request_id"]
            config_change_list = client.get(
                "/api/v1/system/config-changes", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("GET /api/v1/system/config-changes", config_change_list.status_code))
            if config_change_list.status_code != 200 or not config_change_list.json().get("requests"):
                raise SystemExit(f"HTTP smoke failed: config change list -> {config_change_list.status_code} {config_change_list.text}")
            config_change_decision = client.post(
                f"/api/v1/system/config-changes/{config_change_id}/decision",
                headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVE", "decision_note": "HTTP smoke approved"},
            )
            checks.append(("POST /api/v1/system/config-changes/{id}/decision", config_change_decision.status_code))
            if config_change_decision.status_code != 200 or config_change_decision.json().get("status") != "APPROVED":
                raise SystemExit(f"HTTP smoke failed: config change decision -> {config_change_decision.status_code} {config_change_decision.text}")
            config_change_apply = client.post(
                f"/api/v1/system/config-changes/{config_change_id}/apply",
                headers=bearer("approval-smoke-token-12345"),
                json={"note": "HTTP smoke validated"},
            )
            checks.append(("POST /api/v1/system/config-changes/{id}/apply", config_change_apply.status_code))
            if config_change_apply.status_code != 200 or config_change_apply.json().get("status") != "APPLIED":
                raise SystemExit(f"HTTP smoke failed: config change apply -> {config_change_apply.status_code} {config_change_apply.text}")
            config_drift_after = client.get(
                "/api/v1/system/config-drift", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/config-drift after change", config_drift_after.status_code))
            if config_drift_after.status_code != 200 or config_drift_after.json().get("current", {}).get("status") != "IN_SYNC":
                raise SystemExit(f"HTTP smoke failed: config change baseline promotion -> {config_drift_after.status_code} {config_drift_after.text}")
            signing_keys = client.get(
                "/api/v1/system/signing-keys", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/signing-keys", signing_keys.status_code))
            if signing_keys.status_code != 200 or signing_keys.json().get("audit_active_key_id") != "audit-http-v1":
                raise SystemExit(f"HTTP smoke failed: signing keys -> {signing_keys.status_code} {signing_keys.text}")
            cluster = client.get(
                "/api/v1/system/cluster", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/cluster", cluster.status_code))
            if cluster.status_code != 200 or not cluster.json().get("instances"):
                raise SystemExit(f"HTTP smoke failed: cluster -> {cluster.status_code} {cluster.text}")

            db_health = client.get(
                "/api/v1/system/database-health", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/database-health", db_health.status_code))
            if db_health.status_code != 200 or db_health.json().get("integrity") != "ok":
                raise SystemExit(f"HTTP smoke failed: database health -> {db_health.status_code} {db_health.text}")
            db_maintenance = client.post(
                "/api/v1/system/database-maintenance", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("POST /api/v1/system/database-maintenance", db_maintenance.status_code))
            if db_maintenance.status_code != 200 or db_maintenance.json().get("status") != "SUCCESS":
                raise SystemExit(f"HTTP smoke failed: database maintenance -> {db_maintenance.status_code} {db_maintenance.text}")
            db_runs = client.get(
                "/api/v1/system/database-maintenance-runs?limit=5", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/database-maintenance-runs", db_runs.status_code))
            if db_runs.status_code != 200 or not db_runs.json().get("items"):
                raise SystemExit(f"HTTP smoke failed: database maintenance runs -> {db_runs.status_code} {db_runs.text}")

            for path in ["/health", "/health/live", "/health/ready"]:
                response = client.get(path)
                checks.append((path, response.status_code))
                if response.status_code != 200:
                    raise SystemExit(f"HTTP smoke failed: {path} -> {response.status_code}")

            token = client.cookies.get(app_main.CSRF_COOKIE) or client.get("/", headers=admin).cookies.get(app_main.CSRF_COOKIE)
            payload = b"finding_id,product,cve_id,cvss\nSMOKE-1,Smoke Product,CVE-2026-40001,8.2\n"
            imported = client.post(
                "/upload/findings", headers=admin,
                data={"csrf_token": token, "scanner_source": "smoke-scanner", "import_mode": "snapshot"},
                files={"file": ("smoke.csv", payload, "text/csv")}, follow_redirects=False,
            )
            checks.append(("POST /upload/findings", imported.status_code))
            if imported.status_code != 303:
                raise SystemExit(f"HTTP smoke failed: upload -> {imported.status_code}")

            api_payload = b"finding_id,product,cve_id,cvss\nSMOKE-API-1,API Smoke,CVE-2026-40002,7.8\n"
            api_import = client.post(
                "/api/v1/imports/csv?scanner_source=api-smoke&import_mode=incremental",
                headers=bearer("scanner-smoke-token-123456"),
                files={"file": ("api-smoke.csv", api_payload, "text/csv")},
            )
            checks.append(("POST /api/v1/imports/csv", api_import.status_code))
            if api_import.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: API import -> {api_import.status_code}")

            export_job = client.post(
                "/api/v1/exports/findings",
                headers=bearer("scanner-smoke-token-123456"),
                json={"record_state": "ALL", "status": "OPEN"},
            )
            checks.append(("POST /api/v1/exports/findings", export_job.status_code))
            if export_job.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: export queue -> {export_job.status_code} {export_job.text}")
            export_job_id = export_job.json()["job_id"]
            completed_export = None
            for _ in range(50):
                current = client.get(f"/api/v1/jobs/{export_job_id}", headers=bearer("scanner-smoke-token-123456"))
                if current.status_code == 200 and current.json().get("status") in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                    completed_export = current.json()
                    break
                time.sleep(0.1)
            checks.append(("GET /api/v1/jobs/{export_job_id}", 200 if completed_export else 504))
            if not completed_export or completed_export.get("status") != "SUCCEEDED":
                raise SystemExit(f"HTTP smoke failed: export job did not succeed -> {completed_export}")
            artifact_id = (completed_export.get("result") or {}).get("artifact_id")
            artifact = client.get(f"/api/v1/exports/{artifact_id}", headers=bearer("scanner-smoke-token-123456"))
            checks.append(("GET /api/v1/exports/{artifact_id}", artifact.status_code))
            if artifact.status_code != 200 or not artifact.json().get("verification", {}).get("valid"):
                raise SystemExit(f"HTTP smoke failed: export artifact -> {artifact.status_code} {artifact.text}")
            downloaded = client.get(f"/api/v1/exports/{artifact_id}/download", headers=bearer("scanner-smoke-token-123456"))
            checks.append(("GET /api/v1/exports/{artifact_id}/download", downloaded.status_code))
            if downloaded.status_code != 200 or not downloaded.content.startswith(b"\xef\xbb\xbf"):
                raise SystemExit(f"HTTP smoke failed: export download -> {downloaded.status_code}")

            pinned = client.post(
                f"/api/v1/exports/{artifact_id}/pin?pinned=true",
                headers=bearer("admin-smoke-token-1234567"),
            )
            checks.append(("POST /api/v1/exports/{artifact_id}/pin", pinned.status_code))
            if pinned.status_code != 200 or not pinned.json().get("pinned"):
                raise SystemExit(f"HTTP smoke failed: export pin -> {pinned.status_code} {pinned.text}")
            export_listing = client.get("/api/v1/exports", headers=bearer("scanner-smoke-token-123456"))
            checks.append(("GET /api/v1/exports storage", export_listing.status_code))
            if export_listing.status_code != 200 or export_listing.json().get("storage", {}).get("pinned_count") != 1:
                raise SystemExit(f"HTTP smoke failed: export storage -> {export_listing.status_code} {export_listing.text}")
            cleanup = client.post(
                "/api/v1/exports/storage/cleanup", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("POST /api/v1/exports/storage/cleanup", cleanup.status_code))
            if cleanup.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: export cleanup -> {cleanup.status_code} {cleanup.text}")

            second_source_payload = b"finding_id,product,cve_id,cvss,patch_available\nSMOKE-API-B,API Smoke,CVE-2026-40002,9.2,1\n"
            second_source = client.post(
                "/api/v1/imports/csv?scanner_source=api-smoke-b&import_mode=incremental",
                headers=bearer("scanner-smoke-token-123456"),
                files={"file": ("api-smoke-b.csv", second_source_payload, "text/csv")},
            )
            checks.append(("POST /api/v1/imports/csv multi-source", second_source.status_code))
            if second_source.status_code != 200 or second_source.json().get("merged") != 1:
                raise SystemExit(f"HTTP smoke failed: multi-source import -> {second_source.status_code} {second_source.text}")
            sources = client.get("/api/v1/findings/SMOKE-API-1/sources", headers=bearer("scanner-smoke-token-123456"))
            checks.append(("GET /api/v1/findings/{id}/sources", sources.status_code))
            if sources.status_code != 200 or len(sources.json().get("records", [])) != 2:
                raise SystemExit(f"HTTP smoke failed: source detail -> {sources.status_code} {sources.text}")
            source_a = next(item for item in sources.json()["records"] if item["scanner_source"] == "api-smoke")
            resolution = client.post(
                "/api/v1/findings/SMOKE-API-1/source-resolution",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "field_name": "cvss", "chosen_source_record_id": source_a["source_record_id"],
                    "reason": "HTTP smoke authoritative source",
                },
            )
            checks.append(("POST /api/v1/findings/{id}/source-resolution", resolution.status_code))
            if resolution.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: source resolution -> {resolution.status_code} {resolution.text}")
            reconciliation = client.get("/api/v1/reconciliation", headers=bearer("scanner-smoke-token-123456"))
            checks.append(("GET /api/v1/reconciliation", reconciliation.status_code))
            if reconciliation.status_code != 200 or reconciliation.json().get("count", 0) < 1:
                raise SystemExit(f"HTTP smoke failed: reconciliation list -> {reconciliation.status_code} {reconciliation.text}")

            # Asset identity candidate, merge, identifier move, history, and rejection.
            identity_rows = (
                ("identity-a", "HTTP-ID-A", "http-scanner-a-100", "http-shared-host", "CVE-2026-42101"),
                ("identity-b", "HTTP-ID-B", "http-scanner-b-900", "http-shared-host", "CVE-2026-42102"),
            )
            for source, finding_id, asset_id, hostname, cve_id in identity_rows:
                identity_payload = (
                    "finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss\n"
                    f"{finding_id},HTTP Identity,{asset_id},{hostname},prod,{cve_id},identity-lib,1.0,7.5\n"
                ).encode()
                response = client.post(
                    f"/api/v1/imports/csv?scanner_source={source}&import_mode=incremental",
                    headers=bearer("scanner-smoke-token-123456"),
                    files={"file": (f"{source}.csv", identity_payload, "text/csv")},
                )
                checks.append((f"POST /api/v1/imports/csv {source}", response.status_code))
                if response.status_code != 200:
                    raise SystemExit(f"HTTP smoke failed: identity import {source} -> {response.status_code} {response.text}")
            identity_candidates = client.get(
                "/api/v1/asset-identities/candidates", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("GET /api/v1/asset-identities/candidates", identity_candidates.status_code))
            if identity_candidates.status_code != 200 or identity_candidates.json().get("count") != 1:
                raise SystemExit(f"HTTP smoke failed: asset identity candidates -> {identity_candidates.status_code} {identity_candidates.text}")
            identity_candidate = identity_candidates.json()["items"][0]
            identity_target = identity_candidate["asset_ref_id_a"]
            identity_source = identity_candidate["asset_ref_id_b"]
            identity_impact = client.get(
                f"/api/v1/asset-identities/candidates/{identity_candidate['candidate_id']}/impact",
                headers=bearer("scanner-smoke-token-123456"),
                params={"target_asset_ref_id": identity_target},
            )
            checks.append(("GET /api/v1/asset-identities/candidates/{id}/impact", identity_impact.status_code))
            if identity_impact.status_code != 200 or not identity_impact.json().get("can_request"):
                raise SystemExit(f"HTTP smoke failed: asset merge impact -> {identity_impact.status_code} {identity_impact.text}")
            identity_request = client.post(
                f"/api/v1/asset-identities/candidates/{identity_candidate['candidate_id']}/merge-requests",
                headers=bearer("scanner-smoke-token-123456"),
                json={"target_asset_ref_id": identity_target, "reason": "HTTP smoke CMDB confirmation"},
            )
            checks.append(("POST /api/v1/asset-identities/candidates/{id}/merge-requests", identity_request.status_code))
            if identity_request.status_code != 200 or identity_request.json().get("status") != "PENDING":
                raise SystemExit(f"HTTP smoke failed: asset merge request -> {identity_request.status_code} {identity_request.text}")
            unchanged_source = client.get(
                f"/api/v1/assets/{identity_source}", headers=bearer("scanner-smoke-token-123456")
            )
            if unchanged_source.status_code != 200 or unchanged_source.json().get("status") != "ACTIVE":
                raise SystemExit(f"HTTP smoke failed: merge request changed source before approval -> {unchanged_source.text}")
            identity_merge = client.post(
                f"/api/v1/asset-merge-requests/{identity_request.json()['request_id']}/decision",
                headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVED", "decision_note": "HTTP smoke impact and recovery reviewed"},
            )
            checks.append(("POST /api/v1/asset-merge-requests/{id}/decision", identity_merge.status_code))
            if identity_merge.status_code != 200 or identity_merge.json().get("status") != "APPROVED":
                raise SystemExit(f"HTTP smoke failed: asset merge approval -> {identity_merge.status_code} {identity_merge.text}")
            if not identity_merge.json().get("recovery_bundle_sha256"):
                raise SystemExit(f"HTTP smoke failed: asset merge recovery point missing -> {identity_merge.text}")
            identity_identifiers = client.get(
                f"/api/v1/assets/{identity_target}/identifiers", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("GET /api/v1/assets/{id}/identifiers", identity_identifiers.status_code))
            if identity_identifiers.status_code != 200 or identity_identifiers.json().get("count", 0) < 4:
                raise SystemExit(f"HTTP smoke failed: asset identifiers -> {identity_identifiers.status_code} {identity_identifiers.text}")
            identity_history = client.get(
                f"/api/v1/asset-merges?asset_ref_id={identity_target}", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("GET /api/v1/asset-merges", identity_history.status_code))
            if identity_history.status_code != 200 or identity_history.json().get("count") != 1:
                raise SystemExit(f"HTTP smoke failed: asset merge history -> {identity_history.status_code} {identity_history.text}")

            for source, finding_id, asset_id in (
                ("identity-c", "HTTP-ID-C", "http-scanner-c-300"),
                ("identity-d", "HTTP-ID-D", "http-scanner-d-400"),
            ):
                reject_payload = (
                    "finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss\n"
                    f"{finding_id},HTTP Identity,{asset_id},http-reused-host,prod,CVE-2026-42{103 if source.endswith('c') else 104},identity-lib,1.0,7.5\n"
                ).encode()
                response = client.post(
                    f"/api/v1/imports/csv?scanner_source={source}&import_mode=incremental",
                    headers=bearer("scanner-smoke-token-123456"),
                    files={"file": (f"{source}.csv", reject_payload, "text/csv")},
                )
                if response.status_code != 200:
                    raise SystemExit(f"HTTP smoke failed: rejection fixture import -> {response.status_code} {response.text}")
            pending_identity = client.get(
                "/api/v1/asset-identities/candidates", headers=bearer("scanner-smoke-token-123456")
            ).json()["items"]
            reject_candidate = next(item for item in pending_identity if item["asset_name_a"] == "http-reused-host")
            identity_reject = client.post(
                f"/api/v1/asset-identities/candidates/{reject_candidate['candidate_id']}/reject",
                headers=bearer("scanner-smoke-token-123456"),
                json={"reason": "HTTP smoke confirms separate hosts"},
            )
            checks.append(("POST /api/v1/asset-identities/candidates/{id}/reject", identity_reject.status_code))
            if identity_reject.status_code != 200 or identity_reject.json().get("status") != "REJECTED":
                raise SystemExit(f"HTTP smoke failed: asset identity reject -> {identity_reject.status_code} {identity_reject.text}")

            sbom_payload = json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"type": "application", "name": "API Smoke", "version": ""}},
                "components": [{
                    "type": "library", "bom-ref": "pkg:pypi/smoke-lib@1.0",
                    "name": "smoke-lib", "version": "1.0", "purl": "pkg:pypi/smoke-lib@1.0"
                }]
            }).encode()
            component_finding = b"finding_id,product,cve_id,component,component_version,cvss\nSMOKE-SBOM-1,API Smoke,CVE-2026-41001,smoke-lib,1.0,8.1\n"
            component_import = client.post(
                "/api/v1/imports/csv?scanner_source=sbom-smoke&import_mode=incremental",
                headers=bearer("scanner-smoke-token-123456"),
                files={"file": ("sbom-findings.csv", component_finding, "text/csv")},
            )
            if component_import.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: SBOM finding import -> {component_import.status_code} {component_import.text}")
            sbom_import = client.post(
                "/api/v1/sboms", headers=bearer("scanner-smoke-token-123456"),
                data={"notes": "HTTP smoke product release"},
                files={"file": ("api-smoke.cdx.json", sbom_payload, "application/json")},
            )
            checks.append(("POST /api/v1/sboms", sbom_import.status_code))
            if sbom_import.status_code != 200 or len(sbom_import.json().get("links", [])) != 1:
                raise SystemExit(f"HTTP smoke failed: SBOM import -> {sbom_import.status_code} {sbom_import.text}")
            sbom_id = sbom_import.json()["sbom_id"]
            component_id = sbom_import.json()["components"][0]["component_id"]
            link_id = sbom_import.json()["links"][0]["link_id"]
            link_decision = client.post(
                f"/api/v1/sbom-links/{link_id}/decision",
                headers=bearer("scanner-smoke-token-123456"),
                json={"decision": "CONFIRM"},
            )
            checks.append(("POST /api/v1/sbom-links/{id}/decision", link_decision.status_code))
            if link_decision.status_code != 200 or link_decision.json().get("status") != "CONFIRMED":
                raise SystemExit(f"HTTP smoke failed: SBOM link confirm -> {link_decision.status_code} {link_decision.text}")
            vex_create = client.post(
                f"/api/v1/sboms/{sbom_id}/vex", headers=bearer("scanner-smoke-token-123456"),
                json={
                    "component_id": component_id, "cve_id": "CVE-2026-41001",
                    "analysis_state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE",
                    "impact_statement": "disabled code path", "detail": "HTTP smoke review",
                    "finding_id": "SMOKE-SBOM-1"
                },
            )
            checks.append(("POST /api/v1/sboms/{id}/vex", vex_create.status_code))
            if vex_create.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: VEX create -> {vex_create.status_code} {vex_create.text}")
            vex_id = vex_create.json()["vex_id"]
            vex_request = client.post(
                f"/api/v1/vex/{vex_id}/request", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("POST /api/v1/vex/{id}/request", vex_request.status_code))
            if vex_request.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: VEX request -> {vex_request.status_code} {vex_request.text}")
            vex_decision = client.post(
                f"/api/v1/vex/{vex_id}/decision", headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVE", "decision_note": "HTTP smoke approved"},
            )
            checks.append(("POST /api/v1/vex/{id}/decision", vex_decision.status_code))
            if vex_decision.status_code != 200 or vex_decision.json().get("review_status") != "APPROVED":
                raise SystemExit(f"HTTP smoke failed: VEX decision -> {vex_decision.status_code} {vex_decision.text}")
            vex_export = client.get(f"/api/v1/sboms/{sbom_id}/vex", headers=bearer("approval-smoke-token-12345"))
            checks.append(("GET /api/v1/sboms/{id}/vex", vex_export.status_code))
            if vex_export.status_code != 200 or len(vex_export.json().get("vulnerabilities", [])) != 1:
                raise SystemExit(f"HTTP smoke failed: VEX export -> {vex_export.status_code} {vex_export.text}")
            sbom_page = client.get(f"/sboms/{sbom_id}", headers=admin)
            checks.append(("GET /sboms/{id}", sbom_page.status_code))
            if sbom_page.status_code != 200 or "CVE-2026-41001" not in sbom_page.text:
                raise SystemExit(f"HTTP smoke failed: SBOM page -> {sbom_page.status_code}")

            asset_import = client.post(
                "/api/v1/assets", headers=bearer("scanner-smoke-token-123456"),
                json={"items": [{
                    "asset_id": "smoke-asset-1", "asset_name": "Smoke Asset",
                    "service_name": "Smoke Service", "business_unit": "Platform",
                    "owner": "asset-team", "environment": "prod",
                    "criticality": 5, "data_sensitivity": 4, "internet_exposed": True,
                    "tags": "smoke", "status": "ACTIVE"
                }]},
            )
            checks.append(("POST /api/v1/assets", asset_import.status_code))
            if asset_import.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: asset import -> {asset_import.status_code} {asset_import.text}")

            campaign = client.post(
                "/api/v1/campaigns", headers=bearer("scanner-smoke-token-123456"),
                json={
                    "title": "Smoke remediation campaign", "owner": "smoke-api",
                    "due_date": "2026-12-15", "finding_ids": ["SMOKE-API-1"],
                    "apply_workflow": False
                },
            )
            checks.append(("POST /api/v1/campaigns", campaign.status_code))
            if campaign.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: campaign create -> {campaign.status_code} {campaign.text}")
            campaign_id = campaign.json()["campaign_id"]
            campaign_status = client.post(
                f"/api/v1/campaigns/{campaign_id}/status", headers=bearer("scanner-smoke-token-123456"),
                json={"status": "ACTIVE", "expected_row_version": campaign.json()["row_version"]},
            )
            checks.append(("POST /api/v1/campaigns/{id}/status", campaign_status.status_code))
            if campaign_status.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: campaign status -> {campaign_status.status_code} {campaign_status.text}")

            queued_job = client.post(
                "/api/v1/jobs/queue/RESCORE_ALL", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("POST /api/v1/jobs/queue/RESCORE_ALL", queued_job.status_code))
            if queued_job.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: queue job -> {queued_job.status_code}")
            job_detail = client.get(
                f"/api/v1/jobs/{queued_job.json()['job_id']}",
                headers=bearer("scanner-smoke-token-123456"),
            )
            checks.append(("GET /api/v1/jobs/{id}", job_detail.status_code))
            if job_detail.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: job detail -> {job_detail.status_code}")

            current = client.get(
                "/api/v1/findings/SMOKE-API-1", headers=bearer("scanner-smoke-token-123456")
            ).json()
            workflow = client.post(
                "/api/v1/findings/SMOKE-API-1/workflow",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "status": "IN_PROGRESS", "owner": "smoke-api", "due_date": "2026-12-01",
                    "notes": "API smoke", "expected_row_version": current["row_version"],
                },
            )
            checks.append(("POST /api/v1/findings/{id}/workflow", workflow.status_code))
            if workflow.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: API workflow -> {workflow.status_code}")

            mitigated = client.post(
                "/api/v1/findings/SMOKE-API-1/workflow",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "status": "MITIGATED", "owner": "smoke-api", "due_date": "2026-12-01",
                    "notes": "patch applied for retest", "expected_row_version": workflow.json()["row_version"],
                },
            )
            checks.append(("POST /api/v1/findings/{id}/workflow MITIGATED", mitigated.status_code))
            if mitigated.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: mitigated workflow -> {mitigated.status_code} {mitigated.text}")
            verification = client.post(
                "/api/v1/findings/SMOKE-API-1/verification-requests",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "method": "RETEST", "evidence_note": "retest completed",
                    "expected_row_version": mitigated.json()["row_version"],
                },
            )
            checks.append(("POST /api/v1/findings/{id}/verification-requests", verification.status_code))
            if verification.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: verification request -> {verification.status_code} {verification.text}")
            evidence = client.post(
                f"/api/v1/verifications/{verification.json()['verification_id']}/evidence",
                headers=bearer("scanner-smoke-token-123456"),
                data={
                    "notes": "smoke retest log", "source_type": "TICKET_ATTACHMENT",
                    "source_reference": "CHG-SMOKE-17", "acquisition_method": "EXPORT",
                    "collected_at": "2026-07-21T01:00:00+00:00",
                },
                files={"file": ("retest.log", b"retest passed\n", "text/plain")},
            )
            checks.append(("POST /api/v1/verifications/{id}/evidence", evidence.status_code))
            if evidence.status_code != 200 or not evidence.json().get("sha256"):
                raise SystemExit(f"HTTP smoke failed: evidence upload -> {evidence.status_code} {evidence.text}")
            evidence_id = evidence.json()["evidence_id"]
            if evidence.json().get("scan_status") not in {"CLEAN", "WAIVED"}:
                waiver = client.post(
                    f"/api/v1/evidence/{evidence_id}/scan-waiver",
                    headers=bearer("admin-smoke-token-1234567"),
                    json={"reason": "HTTP smoke isolated baseline evidence"},
                )
                checks.append(("POST /api/v1/evidence/{id}/scan-waiver", waiver.status_code))
                if waiver.status_code != 200 or waiver.json().get("scan_status") != "WAIVED":
                    raise SystemExit(f"HTTP smoke failed: evidence scan waiver -> {waiver.status_code} {waiver.text}")
            evidence_download = client.get(
                f"/api/v1/evidence/{evidence_id}/download", headers=bearer("scanner-smoke-token-123456")
            )
            checks.append(("GET /api/v1/evidence/{id}/download", evidence_download.status_code))
            if evidence_download.status_code != 200 or evidence_download.content != b"retest passed\n":
                raise SystemExit("HTTP smoke failed: evidence download")
            custody_transfer = client.post(
                f"/api/v1/evidence/{evidence_id}/custody-transfer",
                headers=bearer("scanner-smoke-token-123456"),
                json={"to_custodian": "approval-team", "purpose": "approval review"},
            )
            checks.append(("POST /api/v1/evidence/{id}/custody-transfer", custody_transfer.status_code))
            if custody_transfer.status_code != 200 or custody_transfer.json().get("current_custodian") != "approval-team":
                raise SystemExit(f"HTTP smoke failed: custody transfer -> {custody_transfer.status_code} {custody_transfer.text}")
            custody = client.get(
                f"/api/v1/evidence/{evidence_id}/custody", headers=bearer("approval-smoke-token-12345")
            )
            checks.append(("GET /api/v1/evidence/{id}/custody", custody.status_code))
            if custody.status_code != 200 or not custody.json().get("integrity", {}).get("valid"):
                raise SystemExit(f"HTTP smoke failed: custody integrity -> {custody.status_code} {custody.text}")
            if custody.json().get("integrity", {}).get("event_count", 0) < 4:
                raise SystemExit(f"HTTP smoke failed: custody event count -> {custody.text}")
            evidence_integrity = client.get(
                "/api/v1/system/evidence-integrity", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/system/evidence-integrity", evidence_integrity.status_code))
            if evidence_integrity.status_code != 200 or not evidence_integrity.json().get("valid"):
                raise SystemExit(f"HTTP smoke failed: evidence integrity -> {evidence_integrity.text}")
            verification_decision = client.post(
                f"/api/v1/verifications/{verification.json()['verification_id']}/decision",
                headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVE", "decision_note": "retest clean"},
            )
            checks.append(("POST /api/v1/verifications/{id}/decision", verification_decision.status_code))
            if verification_decision.status_code != 200 or verification_decision.json().get("status") != "APPROVED":
                raise SystemExit(f"HTTP smoke failed: verification decision -> {verification_decision.status_code} {verification_decision.text}")

            risk_finding = client.get(
                "/api/v1/findings/SMOKE-1", headers=bearer("scanner-smoke-token-123456")
            ).json()
            request = client.post(
                "/api/v1/findings/SMOKE-1/risk-acceptance-requests",
                headers=bearer("scanner-smoke-token-123456"),
                json={
                    "reason": "smoke approval", "exception_expiry": "2027-01-31",
                    "notes": "smoke", "expected_row_version": risk_finding["row_version"],
                },
            )
            checks.append(("POST /api/v1/findings/{id}/risk-acceptance-requests", request.status_code))
            if request.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: approval request -> {request.status_code}")
            decision = client.post(
                f"/api/v1/approvals/{request.json()['request_id']}/decision",
                headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVED", "decision_note": "smoke approved"},
            )
            checks.append(("POST /api/v1/approvals/{id}/decision", decision.status_code))
            if decision.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: approval decision -> {decision.status_code}")

            maintenance = client.post(
                "/maintenance/run", headers=admin, data={"csrf_token": token}, follow_redirects=False
            )
            checks.append(("POST /maintenance/run", maintenance.status_code))
            if maintenance.status_code != 303:
                raise SystemExit(f"HTTP smoke failed: maintenance -> {maintenance.status_code}")

            policy = yaml.safe_load((ROOT / "rules" / "prioritization_policy.yml").read_text(encoding="utf-8"))
            policy["version"] = "2.1.0-smoke"
            policy["name"] = "HTTP smoke candidate policy"
            policy["weights"]["kev"] = int(policy["weights"]["kev"]) + 4
            policy_yaml = yaml.safe_dump(policy, allow_unicode=True, sort_keys=False)
            created_policy = client.post(
                "/api/v1/policies", headers=bearer("admin-smoke-token-1234567"),
                json={"content_yaml": policy_yaml, "notes": "HTTP smoke"},
            )
            checks.append(("POST /api/v1/policies", created_policy.status_code))
            if created_policy.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: policy create -> {created_policy.status_code} {created_policy.text}")
            policy_id = created_policy.json()["policy_id"]
            impact = client.get(
                f"/api/v1/policies/{policy_id}/impact", headers=bearer("admin-smoke-token-1234567")
            )
            checks.append(("GET /api/v1/policies/{id}/impact", impact.status_code))
            if impact.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: policy impact -> {impact.status_code}")
            policy_request = client.post(
                f"/api/v1/policies/{policy_id}/activation-requests",
                headers=bearer("admin-smoke-token-1234567"), json={"reason": "HTTP smoke activation"},
            )
            checks.append(("POST /api/v1/policies/{id}/activation-requests", policy_request.status_code))
            if policy_request.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: policy request -> {policy_request.status_code} {policy_request.text}")
            policy_decision = client.post(
                f"/api/v1/policy-activation-requests/{policy_request.json()['request_id']}/decision",
                headers=bearer("approval-smoke-token-12345"),
                json={"decision": "APPROVED", "decision_note": "HTTP smoke approved"},
            )
            checks.append(("POST /api/v1/policy-activation-requests/{id}/decision", policy_decision.status_code))
            if policy_decision.status_code != 200:
                raise SystemExit(f"HTTP smoke failed: policy decision -> {policy_decision.status_code} {policy_decision.text}")

            queued = client.get("/api/v1/webhooks", headers=bearer("admin-smoke-token-1234567"))
            if queued.status_code != 200 or not queued.json()["items"]:
                raise SystemExit("HTTP smoke failed: webhook events were not queued")
            cluster_end = client.get(
                "/api/v1/system/cluster", headers=bearer("admin-smoke-token-1234567")
            )
            if cluster_end.status_code != 200 or cluster_end.json().get("write_activities"):
                raise SystemExit("HTTP smoke failed: write activity was not cleaned up")

        for path, status in checks:
            print(f"{status} {path}")
        report = ROOT / "reports" / "http_smoke_results.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            "VulnFlow 72.0.84 HTTP TestClient smoke\n"
            f"{len(checks)} checks passed\n"
            "Includes redacted configuration baseline, drift recording, approved configuration change request/decision/promotion, snapshot export queue, artifact SHA-256 download verification, SQL finding pagination metadata, governed asset merge dry-run, operator request, approver recovery point and approval; "
            "portable signed integrity proof create/verify/download; redacted execution receipt UI/API; multi-source reconciliation, candidate rejection, SBOM/VEX, evidence, recovery, policy and automation flows.\n",
            encoding="utf-8",
        )
        print(f"HTTP smoke passed: {len(checks)} checks")


if __name__ == "__main__":
    main()
