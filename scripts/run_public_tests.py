from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TEST_FILES = ['tests/test_app_integration.py', 'tests/test_operations.py', 'tests/test_scoring.py', 'tests/test_scan_lifecycle_v4.py', 'tests/test_rbac_approval_maintenance_v5.py', 'tests/test_policy_governance_v7.py', 'tests/test_background_jobs_v8.py', 'tests/test_recovery_v9.py', 'tests/test_multi_instance_coordination_v10.py', 'tests/test_audit_integrity_v11.py', 'tests/test_asset_campaigns_v13.py', 'tests/test_remediation_verification_v14.py', 'tests/test_evidence_artifacts_v15.py', 'tests/test_evidence_quarantine_v16.py', 'tests/test_evidence_custody_v17.py', 'tests/test_sbom_vex_v18.py', 'tests/test_osv_discovery_v19.py', 'tests/test_multiscanner_reconciliation_v20.py', 'tests/test_asset_identity_v21.py', 'tests/test_asset_merge_governance_v22.py', 'tests/test_asset_merge_rollback_v23.py', 'tests/test_snapshot_exports_v26.py', 'tests/test_config_drift_v29.py', 'tests/test_config_change_control_v30.py', 'tests/test_safe_auth_defaults_v72_0_1.py']

def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.setdefault("VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK", "1")
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TEST_FILES]
    return subprocess.call(command, cwd=root, env=env)

if __name__ == "__main__":
    raise SystemExit(main())
