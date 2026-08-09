from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import production_compose_rehearsal

ROOT = Path(__file__).resolve().parents[1]


def _completed(command: list[str], code: int, *, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(command, code, stdout=stdout, stderr=stderr)


def test_compose_rehearsal_reports_unavailable_when_cli_has_no_engine(monkeypatch) -> None:
    monkeypatch.setattr(production_compose_rehearsal.shutil, "which", lambda name: "docker")

    def fake_run(command: list[str], **kwargs):
        assert command[:2] == ["docker", "info"]
        return _completed(command, 1, stderr="open //./pipe/dockerDesktopLinuxEngine: file not found")

    monkeypatch.setattr(production_compose_rehearsal, "_run", fake_run)
    report = production_compose_rehearsal.run_rehearsal(require_docker=False)
    assert report["status"] == "unavailable"
    assert report["available"] is False
    assert report["passed"] is None
    assert "docker engine unavailable" in report["reason"]


def test_compose_rehearsal_fails_when_required_engine_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(production_compose_rehearsal.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(
        production_compose_rehearsal,
        "_run",
        lambda command, **kwargs: _completed(command, 1, stderr="daemon unavailable"),
    )
    with pytest.raises(RuntimeError, match="docker engine unavailable"):
        production_compose_rehearsal.run_rehearsal(require_docker=True)


def test_runtime_soak_tracks_allocations_before_warmup_and_hides_warmup_samples() -> None:
    source = (ROOT / "scripts/runtime_stability_soak.py").read_text(encoding="utf-8")
    start = source.index("tracemalloc.start()")
    loop = source.index("for index in range(iterations):")
    assert start < loop
    assert "index >= allocation_warmup_iterations" in source
    assert "tracemalloc.reset_peak()" in source
    assert "allocation_tracking_started_here" in source


def test_browser_e2e_uses_rendered_finding_identity_instead_of_stale_copy() -> None:
    source = (ROOT / "tests/e2e/test_vm_workflows.py").read_text(encoding="utf-8")
    assert 'page.locator("nav.breadcrumb").get_by_text("F-0001", exact=True)' in source
    assert '"EdgeConnect Gateway · CVE-2024-3400"' in source
    assert 'page.get_by_text("F-0001 · 정책", exact=False)' not in source
