from __future__ import annotations

"""Run the public core suite in bounded, non-overlapping pytest processes."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

TEST_GROUPS = [['tests/test_production_validation_v81.py',
  'tests/test_pilot_launch_v82.py',
  'tests/test_rbac_approval_maintenance_v5.py',
  'tests/test_project_isolation_v77.py',
  'tests/test_evidence_artifacts_v15.py',
  'tests/test_evidence_custody_v17.py',
  'tests/test_asset_merge_governance_v22.py',
  'tests/test_read_only_recovery_mode_v74.py',
  'tests/test_control_database_separation_v84.py'],
 ['tests/test_background_jobs_v8.py',
  'tests/test_asset_identity_v21.py',
  'tests/test_database_users_v75.py',
  'tests/test_control_recovery_v85.py',
  'tests/test_policy_governance_v7.py',
  'tests/test_evidence_quarantine_v16.py',
  'tests/test_safe_auth_defaults_v72_0_1.py',
  'tests/test_project_operations_v78.py',
  'tests/test_production_security_profile_v86.py'],
 ['tests/test_public_repository_maintenance.py',
  'tests/test_multi_instance_coordination_v10.py',
  'tests/test_sbom_vex_v18.py',
  'tests/test_asset_campaigns_v13.py',
  'tests/test_asset_merge_rollback_v23.py',
  'tests/test_scoring.py',
  'tests/test_config_drift_v29.py',
  'tests/test_live_tls_schema_boundary_v87.py',
  'tests/test_runtime_fault_resilience_v88.py',
  'tests/test_outbound_egress_v89.py',
  'tests/test_smtp_egress_v90.py',
  'tests/test_production_compose_v91.py',
  'tests/test_intelligence_egress_v91.py',
  'tests/test_static_security_boundary_v92.py',
  'tests/test_distribution_install_boundaries_v93.py',
  'tests/test_runtime_dependency_attestation_v94.py',
  'tests/test_windows_external_validation_remediation_v116.py',
  'tests/test_external_validation_windows_followup_v117.py',
  'tests/test_external_validation_windows_finalization_v118.py',
  'tests/test_router_runtime_release_v119.py',
  'tests/test_router_namespace_runtime_v120.py',
  'tests/test_router_source_route_release_v121.py',
  'tests/test_fastapi_router_transfer_v122.py',
  'tests/test_fastapi_callable_cache_release_v123.py',
  'tests/test_locked_local_launchers_v124.py',
  'tests/test_in_memory_router_clone_v125.py',
  'tests/test_context_router_di_v126.py'],
 ['tests/test_offline_deployment_activation_v95.py',
  'tests/test_offline_deployment_history_v96.py',
  'tests/test_offline_deployment_integrity_v97.py',
  'tests/test_offline_deployment_key_lifecycle_v98.py',
  'tests/test_offline_deployment_witness_v99.py',
  'tests/test_offline_deployment_recovery_v100.py',
  'tests/test_offline_deployment_startup_recovery_v101.py',
  'tests/test_offline_deployment_journal_auth_v102.py'],
 ['tests/test_offline_deployment_journal_key_lifecycle_v103.py',
  'tests/test_offline_deployment_journal_key_witness_v104.py',
  'tests/test_external_validation_gate_v105.py',
  'tests/test_external_validation_evidence_binding_v106.py',
  'tests/test_external_validation_signed_exchange_v107.py',
  'tests/test_external_validation_runner_kit_v108.py',
  'tests/test_external_validation_source_attestation_v109.py',
  'tests/test_external_validation_challenge_bound_evidence_v110.py',
  'tests/test_external_validation_authorized_operator_v111.py',
  'tests/test_external_validation_acceptance_ledger_v112.py',
  'tests/test_external_validation_acceptance_checkpoint_v113.py',
  'tests/test_external_validation_checkpoint_series_v114.py',
  'tests/test_external_validation_checkpoint_transfer_v115.py'],
 ['tests/test_scan_lifecycle_v4.py',
  'tests/test_app_integration.py',
  'tests/test_server_rendered_workflows_v93.py',
  'tests/test_osv_discovery_v19.py',
  'tests/test_snapshot_exports_v26.py',
  'tests/test_config_change_control_v30.py',
  'tests/test_audit_integrity_v11.py',
  'tests/test_recovery_drills_v79.py'],
 ['tests/test_recovery_v9.py',
  'tests/test_operations.py',
  'tests/test_multiscanner_reconciliation_v20.py',
  'tests/test_finding_import_wizard_v76.py',
  'tests/test_scanner_anonymization_v83.py',
  'tests/test_collaboration_integrations_v80.py',
  'tests/test_remediation_verification_v14.py',
  'tests/test_commercial_safety_hardening_v73.py']]
TEST_FILES = [item for group in TEST_GROUPS for item in group]


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    import signal
    import time

    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _cleanup_residual_process_group(process: subprocess.Popen[str]) -> None:
    """Kill descendants that survived a successful bounded pytest wrapper exit."""
    if os.name != "posix":
        return
    import signal
    import time

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        return
    time.sleep(0.1)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass


def _run_group(
    command: list[str],
    *,
    root: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> int:
    """Run one bounded wrapper process; only its real exit code can pass."""
    creationflags = 0
    start_new_session = os.name == "posix"
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        command,
        cwd=root,
        env=env,
        start_new_session=start_new_session,
        creationflags=creationflags,
    )
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        print(
            f"pytest group exceeded {timeout_seconds}s; timed-out groups never pass",
            file=sys.stderr,
        )
        return 124
    finally:
        _cleanup_residual_process_group(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--group",
        type=int,
        action="append",
        help="Run only the selected 1-based bounded group; may be repeated.",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.setdefault("VULNFLOW_DEMO_MODE", "1")
    env.setdefault("VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK", "1")
    env.setdefault("VULNFLOW_LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS", "0.2")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.pop("FORCE_COLOR", None)
    env["PY_COLORS"] = "0"
    env["NO_COLOR"] = "1"
    group_timeout = max(30, int(env.get("VULNFLOW_PUBLIC_TEST_GROUP_TIMEOUT_SECONDS", "300")))
    expected_counts = (78, 76, 168, 80, 117, 67, 77)
    selected = list(dict.fromkeys(args.group or range(1, len(TEST_GROUPS) + 1)))
    invalid = [index for index in selected if index < 1 or index > len(TEST_GROUPS)]
    if invalid:
        parser.error(f"group indices must be between 1 and {len(TEST_GROUPS)}: {invalid}")
    passed_groups = 0
    passed_tests = 0
    for index in selected:
        group = TEST_GROUPS[index - 1]
        expected = expected_counts[index - 1]
        print(f"\n=== public regression group {index}/{len(TEST_GROUPS)} ===", flush=True)
        command = [
            sys.executable,
            "scripts/pytest_bounded_group.py",
            "--expected-count",
            str(expected),
            "--",
            "-q",
            "-p",
            "no:cacheprovider",
            *group,
        ]
        returncode = _run_group(
            command,
            root=root,
            env=env,
            timeout_seconds=group_timeout,
        )
        if returncode:
            print(f"public regression group {index} failed", file=sys.stderr)
            return returncode
        passed_groups += 1
        passed_tests += expected
    print(f"public regression suite: PASS ({passed_groups} bounded groups / {passed_tests} collected tests; platform skips remain explicit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
