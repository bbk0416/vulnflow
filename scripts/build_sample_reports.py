from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import yaml

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPORTS = ROOT / "reports"


def main() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vulnflow_samples_") as temp_dir:
        os.environ["VULNFLOW_DB"] = str(Path(temp_dir) / "samples.sqlite3")
        os.environ["VULNFLOW_EVIDENCE_DIR"] = str(Path(temp_dir) / "evidence")
        os.environ["VULNFLOW_RECOVERY_DIR"] = str(Path(temp_dir) / "recovery")
        os.environ["VULNFLOW_EXPORT_DIR"] = str(Path(temp_dir) / "exports")
        os.environ["VULNFLOW_EXPORT_QUOTA_MB"] = "64"
        os.environ["VULNFLOW_EXPORT_MIN_FREE_MB"] = "0"
        os.environ["VULNFLOW_EXPORT_RETENTION_DAYS"] = "7"
        os.environ["VULNFLOW_WEBHOOKS_JSON"] = json.dumps({
            "sample": {
                "url": "http://127.0.0.1:9/vulnflow",
                "secret": "sample-webhook-secret-12345",
                "events": ["*"],
            }
        })
        os.environ["VULNFLOW_WEBHOOK_INTERVAL_SECONDS"] = "0"
        os.environ["VULNFLOW_SIGNING_KEYS_JSON"] = json.dumps({
            "audit-sample-2026q3": "sample-audit-signing-key-2026q3",
            "backup-sample-2026q3": "sample-backup-signing-key-2026q3",
            "audit-sample-2026q2": "sample-retired-audit-key-2026q2",
        })
        os.environ["VULNFLOW_AUDIT_ACTIVE_KEY_ID"] = "audit-sample-2026q3"
        os.environ["VULNFLOW_BACKUP_ACTIVE_KEY_ID"] = "backup-sample-2026q3"
        os.environ["VULNFLOW_AUDIT_REQUIRE_SIGNATURE"] = "1"
        os.environ["VULNFLOW_BACKUP_REQUIRE_SIGNATURE"] = "1"
        os.environ["VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK"] = "1"
        from app import main as app_main

        with TestClient(app_main.app) as client:
            token = client.cookies.get(app_main.CSRF_COOKIE) or client.get("/").cookies.get(app_main.CSRF_COOKIE)
            sample_lines = (ROOT / "data" / "sample_findings.csv").read_bytes().splitlines(keepends=True)
            full_payload = b"".join(sample_lines)
            subset_payload = b"".join(sample_lines[:-1])
            for filename, payload in [("demo-full.csv", full_payload), ("demo-current.csv", subset_payload)]:
                response = client.post(
                    "/upload/findings",
                    data={"csrf_token": token, "scanner_source": "demo-scanner", "import_mode": "snapshot"},
                    files={"file": (filename, payload, "text/csv")},
                    follow_redirects=False,
                )
                if response.status_code != 303:
                    raise SystemExit(f"sample import failed: {filename} -> {response.status_code}")

            # Add a second scanner observation for the same canonical vulnerability.
            # v21 uses the resolved internal asset reference here because scanner display names differ.
            primary_asset_ref = client.get("/api/v1/findings/F-0001").json()["asset_ref_id"]
            secondary_payload = (
                "finding_id,product,product_version,asset_ref_id,asset_id,asset_name,environment,cve_id,component,component_version,cvss,patch_available\n"
                f"QUALYS-EDGE-3400,EdgeConnect Gateway,3.2,{primary_asset_ref},A-EXT-01,external gateway,production,CVE-2024-3400,PAN-OS,10.2.1,9.8,0\n"
            ).encode()
            response = client.post(
                "/upload/findings",
                data={"csrf_token": token, "scanner_source": "qualys-sample", "import_mode": "snapshot"},
                files={"file": ("qualys-edge.csv", secondary_payload, "text/csv")},
                follow_redirects=False,
            )
            if response.status_code != 303:
                raise SystemExit(f"sample secondary scanner import failed: {response.status_code}")

            from app.core.storage import (
                apply_asset_inventory, create_campaign, create_risk_approval_request, get_finding,
                update_campaign_status, update_workflow, create_remediation_verification_request,
                get_source_reconciliation, resolve_source_conflict,
            )
            reconciliation = get_source_reconciliation(app_main.DB_PATH, "F-0001")
            qualys_record = next(item for item in reconciliation["records"] if item["scanner_source"] == "qualys-sample")
            resolve_source_conflict(
                app_main.DB_PATH, "F-0001", field_name="component_version",
                chosen_source_record_id=qualys_record["source_record_id"],
                reason="sample scanner uses the approved appliance inventory feed", actor="sample-operator",
            )
            stale_finding = get_finding(app_main.DB_PATH, "F-0010")
            update_workflow(
                app_main.DB_PATH, "F-0010", status="MITIGATED", owner="플랫폼팀", due_date="",
                exception_expiry="", risk_acceptance_reason="", risk_acceptance_approver="",
                notes="샘플 패치 적용", actor="sample-operator",
                expected_version=stale_finding["row_version"],
            )
            # Repeat the complete snapshot after mitigation so the sample remains valid even
            # when source-level absence counters are introduced or migrated.
            for verification_round in range(app_main.VERIFICATION_ABSENCE_SCANS):
                response = client.post(
                    "/upload/findings",
                    data={"csrf_token": token, "scanner_source": "demo-scanner", "import_mode": "snapshot"},
                    files={"file": (f"demo-verification-{verification_round + 1}.csv", subset_payload, "text/csv")},
                    follow_redirects=False,
                )
                if response.status_code != 303:
                    raise SystemExit(f"sample verification import failed: {response.status_code}")
            verification_finding = get_finding(app_main.DB_PATH, "F-0010")
            verification_request = create_remediation_verification_request(
                app_main.DB_PATH, "F-0010", method="RETEST",
                evidence_note="샘플 재시험에서 취약점 미검출",
                actor="sample-operator", expected_version=verification_finding["row_version"],
                absence_threshold=app_main.VERIFICATION_ABSENCE_SCANS,
            )
            from app.services.evidence import store_verification_evidence, scan_evidence_artifact
            sample_evidence = store_verification_evidence(
                app_main.DB_PATH, app_main.EVIDENCE_DIR,
                verification_id=verification_request["verification_id"],
                filename="sample-retest.log", content=b"scanner retest: finding absent\n",
                notes="샘플 재시험 로그", actor="sample-operator", max_bytes=app_main.MAX_EVIDENCE_BYTES,
                source_type="SCANNER_EXPORT", source_reference="sample-retest-job-17",
                acquisition_method="EXPORT", collected_at="2026-07-21T01:00:00+00:00",
            )
            scan_evidence_artifact(
                app_main.DB_PATH, app_main.EVIDENCE_DIR, sample_evidence["evidence_id"],
                mode="builtin", actor="sample-scanner",
            )
            from app.services.evidence import transfer_evidence_custody, record_evidence_access
            transfer_evidence_custody(
                app_main.DB_PATH, sample_evidence["evidence_id"], actor="sample-operator",
                to_custodian="sample-approver", purpose="sample approval review",
            )
            record_evidence_access(
                app_main.DB_PATH, sample_evidence["evidence_id"], actor="sample-approver",
                purpose="sample evidence review",
            )

            apply_asset_inventory(
                app_main.DB_PATH,
                [{
                    "asset_id": "A-EXT-01", "asset_name": "외부 원격접속 게이트웨이",
                    "service_name": "Remote Access", "business_unit": "Infrastructure",
                    "owner": "네트워크플랫폼팀", "environment": "production",
                    "criticality": 5, "data_sensitivity": 4, "internet_exposed": True,
                    "tags": "edge,external,remote-access", "status": "ACTIVE",
                }], actor="sample-admin",
            )

            # v21 asset identity samples: one reviewed merge and one pending weak match.
            identity_fixtures = (
                ("identity-scan-a", "SAMPLE-ID-A", "sample-a-100", "sample-identity-host", "CVE-2026-21101"),
                ("identity-scan-b", "SAMPLE-ID-B", "sample-b-900", "sample-identity-host", "CVE-2026-21102"),
                ("identity-scan-c", "SAMPLE-ID-C", "sample-c-300", "sample-pending-host", "CVE-2026-21103"),
                ("identity-scan-d", "SAMPLE-ID-D", "sample-d-400", "sample-pending-host", "CVE-2026-21104"),
            )
            for source, finding_id, asset_id, hostname, cve_id in identity_fixtures:
                payload = (
                    "finding_id,product,asset_id,asset_name,environment,cve_id,component,component_version,cvss\n"
                    f"{finding_id},Asset Identity Sample,{asset_id},{hostname},production,{cve_id},identity-agent,1.0,7.5\n"
                ).encode()
                response = client.post(
                    "/upload/findings",
                    data={"csrf_token": token, "scanner_source": source, "import_mode": "incremental"},
                    files={"file": (f"{source}.csv", payload, "text/csv")},
                    follow_redirects=False,
                )
                if response.status_code != 303:
                    raise SystemExit(f"sample asset identity import failed: {source} -> {response.status_code}")
            from app.core.storage import (
                approve_asset_merge_request, create_asset_merge_request,
                list_asset_identity_candidates,
            )
            identity_candidates = list_asset_identity_candidates(app_main.DB_PATH, status="PENDING", limit=100)
            merge_candidate = next(item for item in identity_candidates if item["asset_name_a"] == "sample-identity-host")
            sample_identity_target = str(merge_candidate["asset_ref_id_a"])
            sample_identity_source = str(merge_candidate["asset_ref_id_b"])
            sample_merge_request = create_asset_merge_request(
                app_main.DB_PATH, source_asset_ref_id=sample_identity_source,
                target_asset_ref_id=sample_identity_target,
                candidate_id=merge_candidate["candidate_id"],
                reason="Sample CMDB review confirmed both scanner aliases represent one production host",
                requested_by="sample-operator",
            )
            sample_merge_recovery = app_main._create_asset_merge_recovery_bundle(
                sample_merge_request["request_id"], "sample-approver"
            )
            sample_merge_approved = approve_asset_merge_request(
                app_main.DB_PATH, sample_merge_request["request_id"],
                decided_by="sample-approver", decision_note="Sample impact and recovery point reviewed",
                recovery_bundle_path=sample_merge_recovery["bundle_path"],
                recovery_bundle_sha256=sample_merge_recovery["bundle_sha256"],
            )

            campaign = create_campaign(
                app_main.DB_PATH, title="인터넷 경계 긴급조치",
                description="외부 노출 KEV 항목의 공통 조치 캠페인",
                owner="보안운영팀", due_date="2026-07-31",
                finding_ids=["F-0001", "F-0002"], actor="sample-admin",
            )
            update_campaign_status(
                app_main.DB_PATH, campaign["campaign_id"], status="ACTIVE", actor="sample-admin",
                expected_version=campaign["row_version"],
            )
            app_main.rescore_all(audit=False, actor="sample-admin")
            finding = get_finding(app_main.DB_PATH, "F-0001")
            create_risk_approval_request(
                app_main.DB_PATH, "F-0001", requested_by="sample-operator",
                reason="공급사 패치 일정 확인 중", exception_expiry="2027-01-31",
                notes="월간 완화조치 확인", expected_version=finding["row_version"],
            )
            maintained = client.post(
                "/maintenance/run", data={"csrf_token": token}, follow_redirects=False
            )
            if maintained.status_code != 303:
                raise SystemExit(f"sample maintenance failed: {maintained.status_code}")

            from app.core.storage import (
                create_policy_version, create_policy_activation_request, get_active_policy_version, list_findings
            )
            from app.core.scoring import parse_policy_text, policy_digest
            from app.services.policies import compare_policy_impact, serialize_policy
            active_policy = get_active_policy_version(app_main.DB_PATH)
            candidate = yaml.safe_load((ROOT / "rules" / "prioritization_policy.yml").read_text(encoding="utf-8"))
            candidate["version"] = "2.1.0-sample"
            candidate["name"] = "Sample policy governance candidate"
            candidate["weights"]["kev"] = int(candidate["weights"]["kev"]) + 5
            candidate_yaml = serialize_policy(candidate)
            candidate_record = create_policy_version(
                app_main.DB_PATH, version=candidate["version"], name=candidate["name"],
                content_yaml=candidate_yaml, content_sha256=policy_digest(candidate),
                created_by="sample-admin", notes="샘플 영향분석",
                supersedes_policy_id=active_policy["policy_id"],
            )
            impact = compare_policy_impact(
                list_findings(app_main.DB_PATH), parse_policy_text(active_policy["content_yaml"]), candidate
            )
            create_policy_activation_request(
                app_main.DB_PATH, policy_id=candidate_record["policy_id"], requested_by="sample-admin",
                reason="샘플 정책 변경 검토", impact=impact,
            )

            from app.core.storage import create_background_job
            create_background_job(
                app_main.DB_PATH, job_type="RESCORE_ALL", requested_by="sample-operator",
                dedupe_key="sample-rescore"
            )

            from app.core.storage import create_audit_checkpoint
            signing, audit_key_id, audit_key = app_main._audit_signing()
            create_audit_checkpoint(
                app_main.DB_PATH, signing_key=audit_key, signing_key_id=audit_key_id, actor="sample-admin"
            )

            from app.services.sbom import (
                create_vex_revision, decide_sbom_finding_link, decide_vex_statement, export_cyclonedx_vex,
                parse_cyclonedx_json, request_vex_approval, store_cyclonedx_document,
            )
            import io
            sample_sbom_parsed = parse_cyclonedx_json(
                io.BytesIO((ROOT / "data" / "sample_product_release.cdx.json").read_bytes())
            )
            sample_sbom = store_cyclonedx_document(
                str(app_main.DB_PATH), sample_sbom_parsed, source_filename="sample_product_release.cdx.json",
                actor="sample-operator", notes="Customer Portal 5.8 release sample",
            )
            log4j_component = next(c for c in sample_sbom["components"] if c["name"] == "log4j-core")
            log4j_link = next(link for link in sample_sbom["links"] if link["finding_id"] == "F-0002")
            decide_sbom_finding_link(
                str(app_main.DB_PATH), log4j_link["link_id"], decision="CONFIRM", actor="sample-operator"
            )
            vex_draft = create_vex_revision(
                str(app_main.DB_PATH), sbom_id=sample_sbom["sbom_id"],
                component_id=log4j_component["component_id"], cve_id="CVE-2021-44228",
                analysis_state="EXPLOITABLE", responses=["UPDATE", "WORKAROUND_AVAILABLE"],
                impact_statement="Runtime classpath includes the affected log4j-core release.",
                action_statement="Upgrade to an approved fixed release and retain the current WAF rule until verification.",
                detail="Linked to the Customer Portal finding and reviewed by the sample approver.",
                finding_id="F-0002", actor="sample-operator",
            )
            request_vex_approval(str(app_main.DB_PATH), vex_draft["vex_id"], actor="sample-operator")
            decide_vex_statement(
                str(app_main.DB_PATH), vex_draft["vex_id"], decision="APPROVE",
                decision_note="Sample product security review completed", actor="sample-approver",
            )
            sample_vex_export = export_cyclonedx_vex(str(app_main.DB_PATH), sample_sbom["sbom_id"])

            from app.services.sbom import run_osv_scan, list_osv_matches, list_osv_scans
            class _SampleOsvResponse:
                def __init__(self, status_code, payload):
                    self.status_code = status_code
                    self._payload = payload
                    self.headers = {}
                def json(self):
                    return self._payload
            class _SampleOsvSession:
                def request(self, method, url, **kwargs):
                    if url.endswith("/v1/querybatch"):
                        results = []
                        for query in kwargs["json"].get("queries", []):
                            purl = str((query.get("package") or {}).get("purl") or "")
                            results.append({"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2025-01-01T00:00:00Z"}]} if "log4j-core" in purl else {"vulns": []})
                        return _SampleOsvResponse(200, {"results": results})
                    if "/v1/vulns/" in url:
                        return _SampleOsvResponse(200, {
                            "id": "GHSA-jfh8-c2jp-5v3q", "modified": "2025-01-01T00:00:00Z",
                            "published": "2021-12-10T00:00:00Z", "summary": "Log4Shell remote code execution",
                            "details": "Sample OSV record for offline report generation.",
                            "aliases": ["CVE-2021-44228"],
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
                            "affected": [{"package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
                                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.0"}]}],
                                          "ecosystem_specific": {"severity": "CRITICAL"}}],
                        })
                    raise RuntimeError(url)
                def close(self):
                    pass
            sample_osv_scan = run_osv_scan(
                str(app_main.DB_PATH), sample_sbom["sbom_id"], actor="sample-operator",
                api_base="https://api.osv.dev", session=_SampleOsvSession(), source_job_id="JOB-SAMPLE-OSV",
            )
            sample_osv_matches = list_osv_matches(str(app_main.DB_PATH), sbom_id=sample_sbom["sbom_id"])
            sample_osv_scans = list_osv_scans(str(app_main.DB_PATH), sbom_id=sample_sbom["sbom_id"])

            from app.core.storage import create_asset_merge_rollback_request
            create_asset_merge_rollback_request(
                app_main.DB_PATH, merge_id=sample_merge_approved["merge_id"],
                reason="Sample review found the two scanner aliases should remain separate assets",
                requested_by="sample-operator",
            )

            # Build one verified snapshot export so the release contains UI, JSON metadata,
            # and a downloadable example generated through the same production service.
            from app.services.exports import create_findings_csv_export, set_export_artifact_pinned
            sample_export = create_findings_csv_export(
                app_main.DB_PATH, app_main.EXPORT_DIR, filters={"record_state": "ALL"},
                actor="sample-operator", job_id=None,
                retention_days=app_main.EXPORT_RETENTION_DAYS,
                quota_bytes=app_main.EXPORT_QUOTA_BYTES,
                reserve_bytes=app_main.EXPORT_MIN_FREE_BYTES,
            )
            sample_export = set_export_artifact_pinned(
                app_main.DB_PATH, sample_export["artifact_id"], pinned=True, actor="sample-admin"
            )

            from app.services.config_drift import create_baseline, evaluate_drift, list_baselines, list_drift_checks, record_drift_check
            from app.services.config_changes import (
                create_change_request, decide_change_request, evaluate_change_control, list_change_requests,
            )
            from app.services.recovery import build_config_audit
            sample_audit = build_config_audit(db_path=app_main.DB_PATH, base_dir=ROOT)
            create_baseline(
                app_main.DB_PATH, sample_audit, actor="sample-admin", note="Sample approved configuration"
            )
            record_drift_check(app_main.DB_PATH, sample_audit, actor="sample-auditor")
            target_env = dict(os.environ)
            target_env["VULNFLOW_COOKIE_SECURE"] = "1"
            target_audit = build_config_audit(env=target_env, db_path=app_main.DB_PATH, base_dir=ROOT)
            sample_now = datetime.now(timezone.utc).replace(microsecond=0)
            sample_change = create_change_request(
                app_main.DB_PATH, target_audit, actor="sample-operator",
                title="Enable Secure cookie after TLS rollout",
                reason="Sample approved deployment change",
                rollback_plan="Restore the previous cookie flag and restart the service",
                window_start=(sample_now + timedelta(hours=1)).isoformat(),
                window_end=(sample_now + timedelta(hours=3)).isoformat(),
            )
            decide_change_request(
                app_main.DB_PATH, sample_change["request_id"], actor="sample-approver",
                decision="APPROVE", note="Approved sample change window",
            )

            outputs = {
                "dashboard_preview.html": client.get("/").content,
                "sample_vulnerability_report.html": client.get("/export/report.html").content,
                "sample_prioritized_findings.csv": client.get("/export/findings.csv").content,
                "sample_audit_events.csv": client.get("/export/audit.csv").content,
                "sample_audit_integrity.html": client.get("/audit").content,
                "sample_import_history.html": client.get("/imports").content,
                "sample_reconciliation.html": client.get("/reconciliation").content,
                "sample_jobs.html": client.get("/jobs").content,
                "sample_exports.html": client.get("/exports").content,
                "sample_approvals.html": client.get("/approvals").content,
                "sample_verifications.html": client.get("/verifications").content,
                "sample_finding_evidence.html": client.get("/finding/F-0010").content,
                "sample_maintenance.html": client.get("/maintenance").content,
                "sample_webhooks.html": client.get("/webhooks").content,
                "sample_system_recovery.html": client.get("/system").content,
                "sample_config_changes.html": client.get("/config-changes").content,
                "sample_cluster.html": client.get("/cluster").content,
                "sample_policies.html": client.get(f"/policies?policy_id={candidate_record['policy_id']}").content,
                "sample_assets.html": client.get("/assets").content,
                "sample_asset_identities.html": client.get("/asset-identities?status=").content,
                "sample_exposure_groups.html": client.get("/exposure-groups").content,
                "sample_campaigns.html": client.get("/campaigns").content,
                "sample_campaign.html": client.get(f"/campaigns/{campaign['campaign_id']}").content,
                "sample_sboms.html": client.get("/sboms").content,
                "sample_sbom_release.html": client.get(f"/sboms/{sample_sbom['sbom_id']}").content,
            }
            for name, content in outputs.items():
                (REPORTS / name).write_bytes(content)
            (REPORTS / "sample_sboms.json").write_text(
                json.dumps(client.get("/api/v1/sboms").json(), ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_vex.cdx.json").write_text(
                json.dumps(sample_vex_export, ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_osv_scan.json").write_text(
                json.dumps(sample_osv_scan, ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_osv_matches.json").write_text(
                json.dumps({"items": sample_osv_matches}, ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_osv_scans.json").write_text(
                json.dumps({"items": sample_osv_scans}, ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_summary.json").write_text(
                json.dumps(client.get("/api/v1/summary").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_assets.json").write_text(
                json.dumps(client.get("/api/v1/assets").json(), ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_asset_identity_candidates.json").write_text(
                json.dumps(client.get("/api/v1/asset-identities/candidates?status=").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_asset_merge_requests.json").write_text(
                json.dumps(client.get("/api/v1/asset-merge-requests?status=").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_asset_merge_history.json").write_text(
                json.dumps(client.get("/api/v1/asset-merges").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_asset_merge_rollback_requests.json").write_text(
                json.dumps(client.get("/api/v1/asset-merge-rollback-requests?status=").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_asset_identifiers.json").write_text(
                json.dumps(client.get(f"/api/v1/assets/{sample_identity_target}/identifiers?include_retired=true").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_exposure_groups.json").write_text(
                json.dumps(client.get("/api/v1/exposure-groups").json(), ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_campaigns.json").write_text(
                json.dumps(client.get("/api/v1/campaigns").json(), ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_assets.csv").write_bytes(client.get("/export/assets.csv").content)
            (REPORTS / "sample_campaigns.csv").write_bytes(client.get("/export/campaigns.csv").content)
            (REPORTS / "sample_import_history.json").write_text(
                json.dumps(client.get("/api/v1/imports").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_reconciliation.json").write_text(
                json.dumps(client.get("/api/v1/reconciliation").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_finding_sources.json").write_text(
                json.dumps(client.get("/api/v1/findings/F-0001/sources").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_jobs.json").write_text(
                json.dumps(client.get("/api/v1/jobs").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_exports.json").write_text(
                json.dumps(client.get("/api/v1/exports").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            export_download = client.get(f"/api/v1/exports/{sample_export['artifact_id']}/download")
            if export_download.status_code != 200:
                raise SystemExit(f"sample export download failed: {export_download.status_code}")
            (REPORTS / "sample_findings_snapshot_export.csv").write_bytes(export_download.content)
            (REPORTS / "sample_approvals.json").write_text(
                json.dumps(client.get("/api/v1/approvals").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_verifications.json").write_text(
                json.dumps(client.get("/api/v1/verifications").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            from app.services.evidence import (
                list_evidence_artifacts, verify_evidence_store, list_evidence_custody_events,
                verify_evidence_custody_chain,
            )
            (REPORTS / "sample_evidence_artifacts.json").write_text(
                json.dumps({"items": list_evidence_artifacts(app_main.DB_PATH)}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_evidence_integrity.json").write_text(
                json.dumps(verify_evidence_store(app_main.DB_PATH, app_main.EVIDENCE_DIR), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_evidence_custody.json").write_text(
                json.dumps({
                    "integrity": verify_evidence_custody_chain(app_main.DB_PATH, sample_evidence["evidence_id"]),
                    "items": list_evidence_custody_events(app_main.DB_PATH, sample_evidence["evidence_id"], limit=100),
                }, ensure_ascii=False, indent=2), encoding="utf-8",
            )
            (REPORTS / "sample_maintenance_runs.json").write_text(
                json.dumps(client.get("/api/v1/maintenance-runs").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_webhook_events.json").write_text(
                json.dumps(client.get("/api/v1/webhooks").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_policies.json").write_text(
                json.dumps(client.get("/api/v1/policies").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_metrics.txt").write_text(client.get("/metrics").text, encoding="utf-8")
            (REPORTS / "sample_audit_integrity.json").write_text(
                json.dumps(client.get("/export/audit-integrity.json").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_config_audit.json").write_text(
                json.dumps(client.get("/export/config-audit.json").json(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            current_audit = build_config_audit(db_path=app_main.DB_PATH, base_dir=ROOT)
            current_drift = evaluate_drift(app_main.DB_PATH, current_audit)
            (REPORTS / "sample_config_drift.json").write_text(
                json.dumps({
                    "current": evaluate_change_control(app_main.DB_PATH, current_audit, current_drift),
                    "baselines": list_baselines(app_main.DB_PATH),
                    "checks": list_drift_checks(app_main.DB_PATH),
                }, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (REPORTS / "sample_config_changes.json").write_text(
                json.dumps({
                    "current": evaluate_change_control(app_main.DB_PATH, current_audit, current_drift),
                    "requests": list_change_requests(app_main.DB_PATH),
                }, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            from app.core.signing import collect_signing_key_usage
            config = app_main._signing_config()
            (REPORTS / "sample_signing_keys.json").write_text(
                json.dumps(
                    config.public_summary() | {
                        "usage": collect_signing_key_usage(
                            db_path=str(app_main.DB_PATH), recovery_dir=str(app_main.RECOVERY_DIR),
                            configured_key_ids=sorted(config.keys),
                        )
                    }, ensure_ascii=False, indent=2, sort_keys=True,
                ), encoding="utf-8",
            )
            recovery = client.get("/export/recovery-bundle.zip")
            (REPORTS / "sample_recovery_bundle.zip").write_bytes(recovery.content)

            before = (ROOT / "data" / "sample_sbom.cdx.json").read_bytes()
            after = (ROOT / "data" / "sample_sbom_v2.cdx.json").read_bytes()
            compared = client.post(
                "/upload/sbom-compare",
                data={"csrf_token": token},
                files={
                    "before_file": ("before.cdx.json", before, "application/json"),
                    "after_file": ("after.cdx.json", after, "application/json"),
                },
            )
            if compared.status_code != 200:
                raise SystemExit(f"sample SBOM compare failed: {compared.status_code}")
            (REPORTS / "sample_sbom_compare.html").write_bytes(compared.content)

        # Sample artifacts must not expose an ephemeral absolute build path.
        runtime_prefix = str(Path(temp_dir))
        runtime_prefix_posix = Path(temp_dir).as_posix()
        for artifact in REPORTS.iterdir():
            if not artifact.is_file() or artifact.suffix.lower() not in {".json", ".csv", ".html", ".txt", ".md"}:
                continue
            try:
                text = artifact.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            sanitized = text.replace(runtime_prefix, "<SAMPLE_RUNTIME>").replace(runtime_prefix_posix, "<SAMPLE_RUNTIME>")
            if sanitized != text:
                artifact.write_text(sanitized, encoding="utf-8")

    print("sample reports generated")


if __name__ == "__main__":
    main()
