from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.runtime_stability_soak import _evaluate

ROOT = Path(__file__).resolve().parents[1]


def _checks(samples: list[dict[str, int | None]], *, limit: int = 24 * 1024 * 1024):
    return _evaluate(
        iterations=len(samples),
        samples=samples,
        lifecycle_snapshots=[{"shutdown_timed_out": False, "running_task_count": 0, "pending_task_stacks": []} for _ in samples],
        job_outcomes=[],
        webhook={"accepted": len(samples), "rejected": 0},
        final_database={"integrity": "ok", "schema_version": 46, "active_jobs": 0, "wal_bytes": 0},
        backup_validation={"schema_version": 46, "audit_integrity": {"valid": True}, "finding_count": 0},
        audit_integrity={"valid": True, "issues": []},
        baseline_threads={"portal_ids": [], "count": 1},
        final_threads={"portal_ids": [], "count": 1},
        max_rss_growth_bytes=64 * 1024 * 1024,
        max_python_growth_bytes=limit,
        max_wal_bytes=8 * 1024 * 1024,
    )


def _named(checks: list[dict[str, object]], name: str) -> dict[str, object]:
    return next(item for item in checks if item["name"] == name)


def test_production_compose_rehearsal_runs_as_a_direct_script() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/production_compose_rehearsal.py", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--require-docker" in result.stdout


def test_python_allocation_check_ignores_explicit_warmup_samples() -> None:
    samples = [
        {"rss_bytes": 100, "python_current_bytes": None},
        {"rss_bytes": 100, "python_current_bytes": None},
        {"rss_bytes": 100, "python_current_bytes": None},
        {"rss_bytes": 100, "python_current_bytes": 80 * 1024 * 1024},
        {"rss_bytes": 100, "python_current_bytes": 82 * 1024 * 1024},
        {"rss_bytes": 100, "python_current_bytes": 83 * 1024 * 1024},
    ]
    check = _named(_checks(samples), "python_allocation_growth_bounded")
    assert check["passed"] is True
    assert check["available"] is True
    assert check["measured_samples"] == 3
    assert check["actual_bytes"] == 3 * 1024 * 1024


def test_python_allocation_check_still_rejects_steady_state_growth() -> None:
    samples = [
        {"rss_bytes": 100, "python_current_bytes": None},
        {"rss_bytes": 100, "python_current_bytes": None},
        {"rss_bytes": 100, "python_current_bytes": 10 * 1024 * 1024},
        {"rss_bytes": 100, "python_current_bytes": 40 * 1024 * 1024},
    ]
    check = _named(_checks(samples), "python_allocation_growth_bounded")
    assert check["passed"] is False
    assert check["actual_bytes"] == 30 * 1024 * 1024


def test_browser_e2e_scopes_success_and_expands_approval_history() -> None:
    source = (ROOT / "tests/e2e/test_vm_workflows.py").read_text(encoding="utf-8")
    assert 'page.locator(".notice.success").filter(has_text=text).first' in source
    assert '_advanced_section(admin_page, "예외 승인 이력")' in source
    assert 'approval_history.locator("summary").click()' in source
    assert 'admin_page.get_by_text(re.compile(r"^APPROVED · APR-")).to_be_visible()' not in source
