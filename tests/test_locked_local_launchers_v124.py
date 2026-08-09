from __future__ import annotations

from pathlib import Path

from scripts.dependency_lock import consistency_issues

ROOT = Path(__file__).resolve().parents[1]


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_windows_batch_delegates_to_the_reviewed_powershell_launcher() -> None:
    batch = _text("run_windows.bat")
    assert "run_windows.ps1" in batch
    assert "requirements.txt" not in batch
    assert "requirements.lock" not in batch
    assert "pip install" not in batch.lower()
    assert "uvicorn" not in batch.lower()


def test_powershell_launcher_installs_the_exact_runtime_lock_with_venv_python() -> None:
    launcher = _text("run_windows.ps1")
    assert 'Join-Path $PSScriptRoot "requirements.lock"' in launcher
    assert 'Join-Path $venvRoot "Scripts\\python.exe"' in launcher
    assert '"-m", "pip"' in launcher
    assert '"--requirement", $lockPath' in launcher
    assert 'VULNFLOW_RUNTIME_DEPENDENCY_POLICY = "enforce"' in launcher
    assert "requirements.txt" not in launcher
    assert "pip install --upgrade" not in launcher.lower()
    assert "Activate.ps1" not in launcher
    assert "& $venvPython -m uvicorn" in launcher


def test_linux_launcher_installs_the_exact_runtime_lock_with_venv_python() -> None:
    launcher = _text("run_linux.sh")
    assert 'VENV_PYTHON="$PWD/.venv/bin/python"' in launcher
    assert '"$VENV_PYTHON" -m pip --disable-pip-version-check install' in launcher
    assert '--requirement "$PWD/requirements.lock"' in launcher
    assert 'VULNFLOW_RUNTIME_DEPENDENCY_POLICY:=enforce' in launcher
    assert "requirements.txt" not in launcher
    assert "pip install --upgrade" not in launcher.lower()
    assert 'VULNFLOW_INSTALL_ONLY' in launcher
    assert 'LOCKED_RUNTIME_INSTALLATION=PASS' in launcher
    assert 'enforce_runtime_dependencies(policy="enforce")' in launcher
    assert 'exec "$VENV_PYTHON" -m uvicorn' in launcher


def test_dependency_lock_static_contract_covers_local_launchers() -> None:
    assert consistency_issues(check_installed=False) == []
