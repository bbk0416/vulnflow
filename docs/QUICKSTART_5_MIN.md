# VulnFlow — 5-minute Quick Start

This path is for a first local run of the public repository.

## 1. Requirements

Use **Python 3.12 or 3.13**.

Do not separately run `pip install -r requirements.txt`. The official launchers
manage the dedicated `.venv` and repair the locked environment when required.

## 2. Start VulnFlow

### Windows

```powershell
.\run_windows.ps1
```

### Linux / macOS

```bash
chmod +x run_linux.sh
./run_linux.sh
```

On the first normal-auth run, if no active user exists, the launcher guides you
through creating the first administrator. Enter the new password when prompted,
then enter it again for confirmation.

## 3. Open the login page

Open:

```text
http://127.0.0.1:8000/login
```

Sign in with the administrator account you just created.

## 4. Import your first scanner file

After login, use the import flow for a supported scanner export. The goal of
this quick start is to reach the first usable finding/project view with your own
input, not to claim a customer-validated five-minute result.

## Optional demo reset

Only for the explicit demo workflow:

```bash
VULNFLOW_DEMO_MODE=1 python scripts_reset_demo.py --confirm RESET-DEMO
```

Normal first-run validation should not enable demo mode or the local-admin
fallback.
