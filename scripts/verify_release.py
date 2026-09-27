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
        VerificationStep.create("public-manifest", [python, "scripts/verify_public_manifest.py"], timeout_seconds=120),
        VerificationStep.create("architecture", [python, "scripts/architecture_review.py"], timeout_seconds=60),
        VerificationStep.create("submission-readiness", [python, "scripts/submission_readiness_smoke.py"], timeout_seconds=60),
        VerificationStep.create("safe-auth-defaults", [python, "scripts/safe_auth_defaults_smoke.py"], timeout_seconds=120),
        VerificationStep.create("production-security", [python, "scripts/production_security_rehearsal.py"], timeout_seconds=120),
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
        VerificationStep.create("runtime-fault-rehearsal", [python, "scripts/runtime_fault_rehearsal.py"], timeout_seconds=180),
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
    completed_steps = {
        outcome.name
        for outcome in outcomes
        if outcome.status in {"PASSED", "SKIPPED"}
    }
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if "runtime-dependency-snapshot" in completed_steps:
        runtime_snapshots = sorted(
            (ROOT / "dist").glob(f"vulnflow_runtime_dependencies-{version}-*.tar.gz")
        )
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
