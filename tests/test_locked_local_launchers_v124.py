from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from app.services.accounts import authenticate_user_password, count_active_users
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
    assert '@{ Command = "py"; Arguments = @("-3.13")' in launcher
    assert '@{ Command = "py"; Arguments = @("-3.12")' in launcher
    assert '@{ Command = "python"; Arguments = @()' in launcher
    assert 'Get-FileHash -Algorithm SHA256 $lockPath' in launcher
    assert '.vulnflow-requirements-lock.sha256' in launcher
    assert 'LOCKED_RUNTIME_REUSED=PASS' in launcher
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
    assert 'LOCK_PATH="$PWD/requirements.lock"' in launcher
    assert 'LOCK_MARKER_PATH="$PWD/.venv/.vulnflow-requirements-lock.sha256"' in launcher
    assert "hashlib.sha256" in launcher
    assert 'runtime_ready=0' in launcher
    assert 'LOCKED_RUNTIME_REUSED=PASS' in launcher
    assert 'printf \'%s\' "$LOCK_HASH" > "$LOCK_MARKER_PATH"' in launcher
    assert '--requirement "$LOCK_PATH"' in launcher
    assert 'VULNFLOW_RUNTIME_DEPENDENCY_POLICY:=enforce' in launcher
    assert "requirements.txt" not in launcher
    assert "pip install --upgrade" not in launcher.lower()
    assert 'VULNFLOW_INSTALL_ONLY' in launcher
    assert 'LOCKED_RUNTIME_INSTALLATION=PASS' in launcher
    assert 'enforce_runtime_dependencies(policy="enforce")' in launcher
    assert 'exec "$VENV_PYTHON" -m uvicorn' in launcher


def test_dependency_lock_static_contract_covers_local_launchers(tmp_path: Path) -> None:
    assert consistency_issues(check_installed=False) == []

    base = tmp_path / "first-run"
    data_dir = base / "data"
    control_db = data_dir / "control.db"
    project_db = data_dir / "projects" / "default" / "vulnflow.db"
    password = "First-Run-Admin-42!"
    env = os.environ.copy()
    env.update(
        {
            "VULNFLOW_BASE_DIR": str(base),
            "VULNFLOW_DATA_DIR": str(data_dir),
            "VULNFLOW_CONTROL_DB": str(control_db),
            "VULNFLOW_DEFAULT_PROJECT_DB": str(project_db),
            "VULNFLOW_COORDINATION_DB": str(data_dir / "coordination.db"),
            "VULNFLOW_EVIDENCE_DIR": str(data_dir / "projects" / "default" / "evidence"),
            "VULNFLOW_EXPORT_DIR": str(data_dir / "projects" / "default" / "exports"),
            "VULNFLOW_IMPORT_PREVIEW_DIR": str(data_dir / "projects" / "default" / "import-previews"),
            "VULNFLOW_RECOVERY_DIR": str(data_dir / "projects" / "default" / "backups" / "recovery"),
            "VULNFLOW_DEMO_MODE": "0",
            "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
            "VULNFLOW_JOB_WORKER_ENABLED": "0",
            "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
            "VULNFLOW_WEBHOOK_INTERVAL_SECONDS": "0",
            "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
            "VULNFLOW_BACKUP_INTERVAL_HOURS": "0",
            "VULNFLOW_COOKIE_SECURE": "0",
            "VULNFLOW_UI_LANG": "ko",
        }
    )

    prepared = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.prepare_storage",
            "--control-db",
            str(control_db),
            "--default-project-db",
            str(project_db),
            "--legacy-db",
            str(base / "legacy-vulnflow.db"),
            "--data-dir",
            str(data_dir),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    assert control_db.is_file()
    assert project_db.is_file()
    assert count_active_users(control_db) == 0

    created = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.manage_users",
            "--db",
            str(control_db),
            "create",
            "--username",
            "admin",
            "--role",
            "admin",
            "--password-stdin",
        ],
        cwd=ROOT,
        env=env,
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    assert count_active_users(control_db) == 1
    assert (
        authenticate_user_password(
            control_db,
            username="admin",
            password=password,
            client_key="127.0.0.1",
        ).status
        == "ok"
    )

    login_probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from fastapi.testclient import TestClient\n"
                "from app.main import create_app\n"
                "with TestClient(create_app()) as client:\n"
                "    page = client.get('/login')\n"
                "    assert page.status_code == 200\n"
                "    csrf = client.cookies.get('vulnflow_csrf')\n"
                "    assert csrf\n"
                "    login = client.post('/login', data={'username':'admin','password':'First-Run-Admin-42!','csrf_token':csrf,'next':'/'}, follow_redirects=False)\n"
                "    assert login.status_code == 303 and login.headers['location'] == '/'\n"
                "    home = client.get('/')\n"
                "    assert home.status_code == 200 and 'admin' in home.text\n"
                "print('FIRST_RUN_LOGIN=PASS')\n"
            ),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert login_probe.returncode == 0, login_probe.stdout + login_probe.stderr
    assert "FIRST_RUN_LOGIN=PASS" in login_probe.stdout
