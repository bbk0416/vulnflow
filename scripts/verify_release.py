from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_orchestrator import (
    ReleaseVerificationOrchestrator,
    VerificationStep,
    summarize_outcomes,
)
FORBIDDEN = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}


def build_steps(*, full: bool = False) -> list[VerificationStep]:
    python = sys.executable
    steps = [
        VerificationStep.create("architecture", [python, "scripts/architecture_review.py"], timeout_seconds=60),
        VerificationStep.create("submission-readiness", [python, "scripts/submission_readiness_smoke.py"], timeout_seconds=60),
        VerificationStep.create("safe-auth-defaults", [python, "scripts/safe_auth_defaults_smoke.py"], timeout_seconds=120),
        VerificationStep.create("dependency-lock", [python, "scripts/dependency_lock_smoke.py"], timeout_seconds=120),
        VerificationStep.create("distribution-artifacts", [python, "scripts/distribution_artifact_rehearsal.py"], timeout_seconds=300),
        VerificationStep.create("runtime-dependency-snapshot", [python, "scripts/runtime_dependency_snapshot.py"], timeout_seconds=600),
        VerificationStep.create("release-provenance", [python, "scripts/release_provenance.py"], timeout_seconds=180),
        VerificationStep.create("release-distribution-bundle", [python, "scripts/release_distribution_bundle.py"], timeout_seconds=300),
        VerificationStep.create("offline-deployment-bootstrap", [python, "scripts/offline_deployment_rehearsal.py"], timeout_seconds=600),
        VerificationStep.create("container-deployment-rehearsal", [python, "scripts/container_deployment_rehearsal.py", "--cycles", "2"], timeout_seconds=180),
        VerificationStep.create("upgrade-restore-rehearsal", [python, "scripts/upgrade_restore_rehearsal.py", "--text-output", "reports/upgrade_restore_rehearsal_verification.txt", "--json-output", "reports/upgrade_restore_rehearsal_verification.json"], timeout_seconds=180),
        VerificationStep.create("lifecycle-resources", [python, "scripts/lifecycle_resource_smoke.py"], timeout_seconds=180),
        VerificationStep.create("runtime-stability-soak", [python, "scripts/runtime_stability_soak.py", "--iterations", "12"], timeout_seconds=300),
        VerificationStep.create("release-orchestrator", [python, "scripts/release_orchestrator_smoke.py"], timeout_seconds=180),
        VerificationStep.create("storage-modularization", [python, "scripts/storage_modularization_smoke.py"], timeout_seconds=120),
        VerificationStep.create("internal-storage-facade", [python, "scripts/internal_storage_facade_smoke.py"], timeout_seconds=120),
        VerificationStep.create("main-helper-modularization", [python, "scripts/main_helper_modularization_smoke.py"], timeout_seconds=120),
        VerificationStep.create("application-service-registry", [python, "scripts/application_service_registry_smoke.py"], timeout_seconds=120),
        VerificationStep.create("job-repository-boundary", [python, "scripts/job_repository_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("webhook-repository-boundary", [python, "scripts/webhook_repository_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("proof-trust-boundary", [python, "scripts/proof_trust_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("integrity-proof-boundary", [python, "scripts/integrity_proof_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("trust-router-boundary", [python, "scripts/trust_router_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("governance-router-boundary", [python, "scripts/governance_router_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("application-context-boundary", [python, "scripts/application_context_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("finding-write-boundary", [python, "scripts/finding_write_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("asset-write-boundary", [python, "scripts/asset_write_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("application-runtime-boundary", [python, "scripts/application_runtime_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("asgi-runtime-boundary", [python, "scripts/asgi_runtime_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("endpoint-workflow-boundary", [python, "scripts/endpoint_workflow_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("job-runtime-boundary", [python, "scripts/job_runtime_boundary_smoke.py"], timeout_seconds=120),
        VerificationStep.create("operation-guard", [python, "scripts/operation_guard_smoke.py"], timeout_seconds=120),
        VerificationStep.create("transactions", [python, "scripts/transaction_runtime_smoke.py"], timeout_seconds=120),
        VerificationStep.create("retry-policy", [python, "scripts/retry_policy_smoke.py"], timeout_seconds=120),
        VerificationStep.create("idempotency", [python, "scripts/idempotency_smoke.py"], timeout_seconds=120),
        VerificationStep.create("execution-receipts", [python, "scripts/execution_receipt_smoke.py"], timeout_seconds=120),
        VerificationStep.create("receipt-retention", [python, "scripts/execution_receipt_retention_smoke.py"], timeout_seconds=120),
        VerificationStep.create("integrity-proof-hmac", [python, "scripts/integrity_proof_smoke.py"], timeout_seconds=120),
        VerificationStep.create("integrity-proof-ed25519", [python, "scripts/public_integrity_proof_smoke.py"], timeout_seconds=120),
        VerificationStep.create("proof-key-rotation", [python, "scripts/proof_key_rotation_smoke.py"], timeout_seconds=120),
        VerificationStep.create("proof-key-revocation", [python, "scripts/proof_key_revocation_smoke.py"], timeout_seconds=120),
        VerificationStep.create("revocation-checkpoint", [python, "scripts/revocation_checkpoint_smoke.py"], timeout_seconds=120),
        VerificationStep.create("checkpoint-witness", [python, "scripts/checkpoint_witness_smoke.py"], timeout_seconds=120),
        VerificationStep.create("transparency-log", [python, "scripts/transparency_log_smoke.py"], timeout_seconds=120),
        VerificationStep.create("transparency-mirror", [python, "scripts/transparency_mirror_smoke.py"], timeout_seconds=120),
        VerificationStep.create("mirror-consistency", [python, "scripts/mirror_consistency_smoke.py"], timeout_seconds=120),
    ]
    test_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "tests").glob("test_*.py"))
    for index, group in enumerate([test_files[offset::3] for offset in range(3)], start=1):
        steps.append(VerificationStep.create(
            f"pytest-{index}",
            [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", *group],
            timeout_seconds=360,
        ))
    steps.append(VerificationStep.create(
        "release-metadata",
        [python, "scripts/release_metadata.py", "--check", "--collect-tests"],
        timeout_seconds=300,
    ))
    steps.extend([
        VerificationStep.create("benchmark", [python, "scripts/run_benchmark.py"], timeout_seconds=120),
        VerificationStep.create("query-performance", [python, "scripts/query_performance_smoke.py"], timeout_seconds=300),
        VerificationStep.create("snapshot-export", [python, "scripts/export_snapshot_smoke.py"], timeout_seconds=300),
        VerificationStep.create("export-storage", [python, "scripts/export_storage_smoke.py"], timeout_seconds=180),
        VerificationStep.create("database-maintenance", [python, "scripts/database_maintenance_smoke.py"], timeout_seconds=180),
        VerificationStep.create("config-drift", [python, "scripts/config_drift_smoke.py"], timeout_seconds=120),
        VerificationStep.create("config-change-control", [python, "scripts/config_change_control_smoke.py"], timeout_seconds=120),
        VerificationStep.create("http", [python, "scripts/http_smoke.py"], timeout_seconds=300),
    ])
    if full:
        steps.append(VerificationStep.create("coverage-verification", [python, "scripts/coverage_verification.py"], timeout_seconds=3600))
        for name, script, timeout in (
            ("uvicorn", "scripts/uvicorn_smoke.py", 240),
            ("job-worker", "scripts/job_worker_smoke.py", 180),
            ("cluster", "scripts/cluster_smoke.py", 240),
            ("webhook", "scripts/webhook_smoke.py", 180),
            ("signing-rotation", "scripts/signing_rotation_smoke.py", 300),
            ("evidence-scan", "scripts/evidence_scan_smoke.py", 180),
            ("evidence-custody", "scripts/evidence_custody_smoke.py", 180),
            ("sbom-vex", "scripts/sbom_vex_smoke.py", 180),
            ("osv-discovery", "scripts/osv_discovery_smoke.py", 180),
            ("osv-http", "scripts/osv_http_smoke.py", 180),
            ("reconciliation", "scripts/reconciliation_smoke.py", 180),
            ("asset-identity", "scripts/asset_identity_smoke.py", 180),
        ):
            steps.append(VerificationStep.create(name, [python, script], timeout_seconds=timeout))
    return steps


def write_summary(summary: dict[str, object]) -> None:
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "orchestrator_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow release verification summary",
        "",
        f"total steps: {summary['total']}",
        f"passed: {summary['passed']}",
        f"resumed: {summary['skipped']}",
        f"failed: {summary['failed']}",
        f"duration_ms: {summary['duration_ms']}",
    ]
    (reports / "orchestrator_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded, resumable VulnFlow release verification.")
    parser.add_argument("--resume", action="store_true", help="Skip successful steps from a matching journal.")
    parser.add_argument("--full", action="store_true", help="Include real-process and integration smoke tests.")
    parser.add_argument("--from-step", default=None, help="Start at the named verification step.")
    parser.add_argument("--only", action="append", default=[], help="Run only the named step; repeatable.")
    parser.add_argument("--list", action="store_true", help="List verification step names and exit.")
    parser.add_argument(
        "--journal",
        default=os.getenv(
            "VULNFLOW_RELEASE_VERIFY_JOURNAL",
            str(Path(tempfile.gettempdir()) / f"vulnflow-{ROOT.name}-release-journal.json"),
        ),
    )
    args = parser.parse_args()

    for path in list((ROOT / "app").rglob("*.py")) + list((ROOT / "scripts").rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    full = args.full or os.getenv("VULNFLOW_FULL_RELEASE_VERIFY", "").strip() == "1"
    steps = build_steps(full=full)
    if args.list:
        for step in steps:
            print(step.name)
        return
    orchestrator = ReleaseVerificationOrchestrator(
        root=ROOT, journal_path=args.journal, resume=args.resume
    )
    outcomes = orchestrator.run(
        steps, only=set(args.only) if args.only else None, start_from=args.from_step
    )
    write_summary(summarize_outcomes(outcomes))

    dirty = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.name in FORBIDDEN or p.suffix == ".pyc"]
    if dirty:
        raise SystemExit("release contains cache artifacts: " + ", ".join(dirty[:10]))
    required = [
        "README.md", "VERSION", "LICENSE", "SECURITY.md", "Dockerfile", "bom.cdx.json",
        "reports/coverage_verification_summary.json",
        "reports/coverage_verification.txt",
        "reports/submission_readiness_verification.txt",
        ".github/workflows/full-release.yml",
        "docs/06_DATA_SCHEMA.md", "docs/09_BACKUP_RESTORE.md", "docs/11_COMPLETION_CHECKLIST.md",
        "docs/12_RBAC_APPROVALS.md", "docs/13_MAINTENANCE_RETENTION.md",
        "docs/14_API_TOKENS_AUTOMATION.md", "docs/15_WEBHOOKS_OBSERVABILITY.md",
        "docs/16_POLICY_GOVERNANCE.md", "docs/17_BACKGROUND_JOBS.md",
        "docs/18_RECOVERY_BUNDLES_CONFIG_AUDIT.md", "docs/19_MULTI_INSTANCE_COORDINATION.md",
        "docs/20_AUDIT_INTEGRITY.md", "docs/21_SIGNING_KEY_ROTATION.md",
        "docs/22_ASSET_INVENTORY_CAMPAIGNS.md", "docs/23_REMEDIATION_VERIFICATION.md",
        "docs/24_VERIFICATION_EVIDENCE_STORE.md", "docs/25_EVIDENCE_QUARANTINE_MALWARE_SCAN.md",
        "docs/26_EVIDENCE_CHAIN_OF_CUSTODY.md", "docs/27_SBOM_VEX_SUPPLY_CHAIN.md",
        "docs/28_OSV_SUPPLY_CHAIN_DISCOVERY.md", "docs/29_MULTI_SCANNER_RECONCILIATION.md",
        "docs/30_ASSET_IDENTITY_RESOLUTION.md", "docs/31_ASSET_MERGE_GOVERNANCE.md",
        "docs/32_ASSET_MERGE_SCOPED_ROLLBACK.md", "docs/33_SQL_QUERY_PAGINATION_PERFORMANCE.md",
        "docs/34_FTS_CURSOR_PAGINATION.md", "docs/35_SNAPSHOT_EXPORT_ARTIFACTS.md",
        "docs/36_EXPORT_STORAGE_GOVERNANCE.md", "docs/37_SQLITE_ONLINE_MAINTENANCE.md",
        "docs/38_CONFIGURATION_BASELINE_DRIFT.md", "docs/39_CONFIGURATION_CHANGE_CONTROL.md", "docs/40_ARCHITECTURE_REVIEW_MODULARIZATION.md",
        "docs/41_DOMAIN_ROUTER_MODULARIZATION.md", "docs/42_REPOSITORY_BOUNDARY_MODULARIZATION.md",
        "docs/43_WRITE_REPOSITORY_MODULARIZATION.md", "docs/44_APPLICATION_FACTORY_CONTEXT.md",
        "docs/45_IMMUTABLE_RUNTIME_DEPENDENCIES.md", "docs/46_ROUTER_RUNTIME_ISOLATION.md", "docs/47_CONTEXT_BOUND_LIFECYCLE_ORCHESTRATION.md",
        "docs/48_CONTEXT_BOUND_OPERATION_GUARD.md", "docs/49_CONTEXT_BOUND_SQLITE_TRANSACTIONS.md",
        "docs/50_DURABLE_RETRY_POLICY.md", "docs/51_DURABLE_IDEMPOTENCY_LEDGER.md", "docs/52_REDACTED_EXECUTION_RECEIPTS.md", "docs/53_EXECUTION_RECEIPT_RETENTION_ARCHIVES.md", "docs/54_PORTABLE_INTEGRITY_PROOFS.md", "docs/55_ED25519_PUBLIC_INTEGRITY_PROOFS.md", "docs/56_ED25519_KEY_ROTATION_TRUST_CHAINS.md", "docs/57_EMERGENCY_ED25519_KEY_REVOCATION.md", "docs/58_REVOCATION_REGISTRY_CHECKPOINTS.md", "docs/59_CHECKPOINT_WITNESS_QUORUM.md", "docs/60_APPEND_ONLY_PROOF_TRANSPARENCY_LOG.md", "docs/61_TRANSPARENCY_MIRROR_GOSSIP.md", "docs/62_CROSS_MIRROR_CONSISTENCY_CHECKPOINTS.md", "docs/63_DETERMINISTIC_LIFECYCLE_RESOURCE_SHUTDOWN.md", "docs/64_RESUMABLE_RELEASE_VERIFICATION.md", "docs/65_STORAGE_ORCHESTRATION_MODULARIZATION.md", "docs/66_INTERNAL_STORAGE_FACADE_BOUNDARY.md", "docs/67_MAIN_HELPER_BOUNDARY_MODULARIZATION.md", "docs/68_APPLICATION_SERVICE_REGISTRY.md", "docs/69_BACKGROUND_JOB_REPOSITORY_BOUNDARIES.md", "docs/70_PROOF_TRUST_BOUNDARIES.md", "docs/71_TRUST_ROUTER_BOUNDARIES.md", "docs/72_GOVERNANCE_ROUTER_BOUNDARIES.md", "docs/73_APPLICATION_CONTEXT_BOUNDARIES.md", "docs/74_FINDING_WRITE_REPOSITORY_BOUNDARIES.md", "docs/75_ASSET_WRITE_REPOSITORY_BOUNDARIES.md", "docs/76_APPLICATION_RUNTIME_BOUNDARIES.md", "docs/77_BACKGROUND_JOB_RUNTIME_BOUNDARIES.md", "docs/78_ENDPOINT_WORKFLOW_BOUNDARIES.md", "docs/79_INTEGRITY_PROOF_BOUNDARIES.md", "docs/80_WEBHOOK_REPOSITORY_BOUNDARIES.md", "docs/81_SPLIT_ASGI_RUNTIME_BOUNDARIES.md",
        "docs/92_SUBMISSION_STABILIZATION.md",
        "scripts/lifecycle_resource_smoke.py", "scripts/release_orchestrator.py", "scripts/release_orchestrator_smoke.py", "scripts/storage_modularization_smoke.py", "scripts/internal_storage_facade_smoke.py", "scripts/main_helper_modularization_smoke.py", "scripts/application_service_registry_smoke.py", "scripts/job_repository_boundary_smoke.py", "scripts/webhook_repository_boundary_smoke.py", "scripts/proof_trust_boundary_smoke.py", "scripts/trust_router_boundary_smoke.py", "scripts/governance_router_boundary_smoke.py", "scripts/application_context_boundary_smoke.py", "scripts/finding_write_boundary_smoke.py", "scripts/asset_write_boundary_smoke.py", "scripts/application_runtime_boundary_smoke.py", "scripts/asgi_runtime_boundary_smoke.py", "scripts/endpoint_workflow_boundary_smoke.py", "scripts/integrity_proof_boundary_smoke.py", "scripts/operation_guard_smoke.py", "scripts/transaction_runtime_smoke.py", "scripts/retry_policy_smoke.py", "scripts/idempotency_smoke.py", "scripts/execution_receipt_smoke.py", "scripts/execution_receipt_retention_smoke.py", "scripts/integrity_proof_smoke.py", "scripts/public_integrity_proof_smoke.py", "scripts/proof_key_rotation_smoke.py", "scripts/proof_key_revocation_smoke.py", "scripts/revocation_checkpoint_smoke.py", "scripts/checkpoint_witness_smoke.py", "scripts/transparency_log_smoke.py", "scripts/transparency_mirror_smoke.py", "scripts/mirror_consistency_smoke.py", "scripts/verify_integrity_proof.py", "scripts/generate_integrity_proof_key.py",
        "scripts/evidence_scan_smoke.py", "scripts/evidence_custody_smoke.py", "scripts/sbom_vex_smoke.py",
        "scripts/osv_discovery_smoke.py", "scripts/osv_http_smoke.py", "scripts/reconciliation_smoke.py",
        "scripts/asset_identity_smoke.py", "scripts/query_performance_smoke.py", "scripts/export_snapshot_smoke.py",
        "scripts/export_storage_smoke.py", "scripts/database_maintenance_smoke.py", "scripts/config_drift_smoke.py",
        "scripts/config_change_control_smoke.py",
        "app/templates/webhooks.html", "app/templates/policies.html", "app/templates/jobs.html",
        "app/templates/system.html", "app/templates/cluster.html", "app/templates/audit.html", "app/templates/proof_witnesses.html", "app/templates/execution_receipts.html",
        "app/templates/assets.html", "app/templates/asset.html", "app/templates/exposure_groups.html",
        "app/templates/campaigns.html", "app/templates/campaign.html", "app/templates/verifications.html",
        "app/templates/sboms.html", "app/templates/sbom_detail.html", "app/templates/reconciliation.html",
        "app/templates/asset_identities.html", "app/templates/exports.html", "app/templates/config_changes.html",
        "reports/sample_finding_evidence.html", "reports/sample_evidence_artifacts.json",
        "reports/sample_evidence_integrity.json", "reports/sample_evidence_custody.json",
        "reports/evidence_custody_verification.txt", "reports/sample_audit_integrity.json",
        "reports/sample_audit_integrity.html", "reports/sample_signing_keys.json",
        "reports/sample_assets.html", "reports/sample_assets.json", "reports/sample_assets.csv",
        "reports/sample_exposure_groups.html", "reports/sample_exposure_groups.json",
        "reports/sample_campaigns.html", "reports/sample_campaigns.json", "reports/sample_campaigns.csv",
        "reports/sample_campaign.html", "reports/sample_verifications.html",
        "reports/sample_verifications.json", "reports/sample_sboms.html", "reports/sample_sbom_release.html",
        "reports/sample_sboms.json", "reports/sample_vex.cdx.json", "reports/sbom_vex_verification.txt",
        "reports/sample_osv_scan.json", "reports/sample_osv_matches.json", "reports/sample_osv_scans.json",
        "reports/osv_discovery_verification.txt", "reports/osv_http_verification.txt",
        "reports/reconciliation_verification.txt", "reports/sample_reconciliation.html",
        "reports/asset_identity_verification.txt", "reports/sample_asset_identities.html",
        "reports/sample_asset_identity_candidates.json", "reports/sample_asset_merge_requests.json", "reports/sample_asset_merge_history.json",
        "reports/sample_asset_merge_rollback_requests.json",
        "reports/sample_asset_identifiers.json",
        "reports/query_performance_verification.txt", "reports/query_performance_verification.json",
        "reports/export_snapshot_verification.txt", "reports/export_snapshot_verification.json",
        "reports/export_storage_governance_verification.txt", "reports/export_storage_governance_verification.json",
        "reports/database_maintenance_verification.txt", "reports/database_maintenance_verification.json",
        "reports/config_drift_verification.txt", "reports/config_drift_verification.json",
        "reports/sample_config_drift.json", "reports/sample_config_changes.html", "reports/sample_config_changes.json",
        "reports/lifecycle_resource_verification.txt", "reports/lifecycle_resource_verification.json", "reports/release_orchestrator_verification.txt", "reports/release_orchestrator_verification.json", "reports/storage_modularization_verification.txt", "reports/storage_modularization_verification.json", "reports/internal_storage_facade_verification.txt", "reports/internal_storage_facade_verification.json", "reports/main_helper_modularization_verification.txt", "reports/main_helper_modularization_verification.json", "reports/application_service_registry_verification.txt", "reports/application_service_registry_verification.json", "reports/job_repository_boundary_verification.txt", "reports/webhook_repository_boundary_verification.txt", "reports/webhook_repository_boundary_verification.json", "reports/proof_trust_boundary_verification.txt", "reports/proof_trust_boundary_verification.json", "reports/trust_router_boundary_verification.txt", "reports/trust_router_boundary_verification.json", "reports/governance_router_boundary_verification.txt", "reports/governance_router_boundary_verification.json", "reports/application_context_boundary_verification.txt", "reports/application_context_boundary_verification.json", "reports/finding_write_boundary_verification.txt", "reports/finding_write_boundary_verification.json", "reports/asset_write_boundary_verification.txt", "reports/asset_write_boundary_verification.json", "reports/application_runtime_boundary_verification.txt", "reports/application_runtime_boundary_verification.json", "reports/asgi_runtime_boundary_verification.txt", "reports/asgi_runtime_boundary_verification.json", "reports/endpoint_workflow_boundary_verification.txt", "reports/endpoint_workflow_boundary_verification.json", "reports/integrity_proof_boundary_verification.txt", "reports/integrity_proof_boundary_verification.json", "reports/job_runtime_boundary_verification.txt", "reports/job_runtime_boundary_verification.json", "reports/operation_guard_verification.txt", "reports/operation_guard_verification.json",
        "reports/runtime_stability_soak_verification.txt", "reports/runtime_stability_soak_verification.json", "scripts/runtime_stability_soak.py", "docs/85_RUNTIME_STABILITY_SOAK.md",
        "reports/container_deployment_rehearsal_verification.txt", "reports/container_deployment_rehearsal_verification.json", "scripts/container_deployment_rehearsal.py", "docs/86_CONTAINER_DEPLOYMENT_REHEARSAL.md",
        "reports/transaction_runtime_verification.txt", "reports/transaction_runtime_verification.json",
        "reports/retry_policy_verification.txt", "reports/retry_policy_verification.json",
        "reports/idempotency_verification.txt", "reports/idempotency_verification.json",
        "reports/execution_receipt_verification.txt", "reports/execution_receipt_verification.json",
        "reports/execution_receipt_retention_verification.txt", "reports/execution_receipt_retention_verification.json",
        "reports/integrity_proof_verification.txt", "reports/integrity_proof_verification.json",
        "reports/public_integrity_proof_verification.txt", "reports/public_integrity_proof_verification.json",
        "reports/proof_key_rotation_verification.txt", "reports/proof_key_rotation_verification.json",
        "reports/proof_key_revocation_verification.txt", "reports/proof_key_revocation_verification.json",
        "reports/revocation_checkpoint_verification.txt", "reports/revocation_checkpoint_verification.json",
        "reports/checkpoint_witness_verification.txt", "reports/checkpoint_witness_verification.json",
        "reports/transparency_log_verification.txt", "reports/transparency_log_verification.json",
        "reports/transparency_mirror_verification.txt", "reports/transparency_mirror_verification.json",
        "reports/mirror_consistency_verification.txt", "reports/mirror_consistency_verification.json",
        "reports/config_change_control_verification.txt", "reports/config_change_control_verification.json",
        "reports/sample_exports.html", "reports/sample_exports.json", "reports/sample_findings_snapshot_export.csv",
        "reports/sample_reconciliation.json", "reports/sample_finding_sources.json", "reports/safe_auth_defaults_verification.txt", "reports/safe_auth_defaults_verification.json", "reports/dependency_lock_verification.txt", "reports/dependency_lock_verification.json", "reports/upgrade_restore_rehearsal_verification.txt", "reports/upgrade_restore_rehearsal_verification.json", "tests/fixtures/v48_schema35.sqlite3.gz", "tests/fixtures/v48_schema35_fixture.json", "scripts/upgrade_restore_rehearsal.py", "docs/84_CROSS_VERSION_UPGRADE_AND_RECOVERY_REHEARSAL.md", "reports/release_manifest.json", "reports/orchestrator_summary.txt", "reports/orchestrator_summary.json", "requirements.lock", "requirements-dev.lock", ".python-version", "docs/83_DEPENDENCY_LOCK_AND_BUILD_REPRODUCIBILITY.md", ".env.example", "pyproject.toml", "MANIFEST.in", "scripts/distribution_artifact_rehearsal.py", "docs/87_REPRODUCIBLE_DISTRIBUTION_ARTIFACTS.md", "reports/distribution_artifact_rehearsal_verification.txt", "reports/distribution_artifact_rehearsal_verification.json", "scripts/runtime_dependency_snapshot.py", "docs/88_OFFLINE_RUNTIME_DEPENDENCY_SNAPSHOT.md", "reports/runtime_dependency_snapshot_verification.txt", "reports/runtime_dependency_snapshot_verification.json", "dist/runtime_dependency_snapshot_manifest.json", "dist/RUNTIME_SNAPSHOT_SHA256SUMS.txt", "dist/bbk_vulnflow-72.0.13-py3-none-any.whl", "dist/bbk_vulnflow-72.0.13.tar.gz", "dist/SHA256SUMS.txt", "scripts/release_distribution_bundle.py", "scripts/verify_release_distribution.py", "docs/90_SIGNED_RELEASE_DISTRIBUTION_BUNDLE.md", "reports/release_distribution_bundle_verification.txt", "reports/release_distribution_bundle_verification.json", "scripts/offline_deployment_bootstrap.py", "scripts/offline_deployment_rehearsal.py", "docs/91_SIGNED_OFFLINE_DEPLOYMENT_BOOTSTRAP.md", "reports/offline_deployment_bootstrap_verification.txt", "reports/offline_deployment_bootstrap_verification.json",
    ]
    missing = [name for name in required if not (ROOT / name).exists()]
    if missing:
        raise SystemExit("missing release files: " + ", ".join(missing))
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if version != "72.0.13":
        raise SystemExit(f"unexpected VERSION: {version}")
    runtime_snapshots = sorted((ROOT / "dist").glob(f"vulnflow_runtime_dependencies-{version}-*.tar.gz"))
    if len(runtime_snapshots) != 1:
        raise SystemExit(f"expected one runtime dependency snapshot: {runtime_snapshots}")
    forbidden_runtime = [
        str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
        if p.is_file() and (p.name in {"vulnflow.db", "vulnflow-coordination.db"} or p.name.endswith(("-wal", "-shm")))
    ]
    if forbidden_runtime:
        raise SystemExit("release contains runtime database artifacts: " + ", ".join(forbidden_runtime))
    print("release verification passed")


if __name__ == "__main__":
    main()
