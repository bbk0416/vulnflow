# VulnFlow 72.0.66 — Locked local runtime installation

VulnFlow 72.0.66 removes the dependency drift between the verified release environment and the ordinary Windows/Linux launch path. Previous local launchers installed only `requirements.txt`, allowing transitive packages to resolve differently from the tested `requirements.lock` closure. They also upgraded `pip` on every launch and depended on shell activation to select the intended interpreter.

## Changes

- Install the exact runtime closure from `requirements.lock` in the reviewed PowerShell and POSIX launchers.
- Execute installation, storage preparation, account management, and Uvicorn through the virtual environment's absolute Python path.
- Remove the unpinned `pip install --upgrade pip` step from ordinary startup.
- Make `run_windows.bat` a thin wrapper around the reviewed PowerShell launcher instead of maintaining a second installation path.
- Default local launcher dependency attestation to `VULNFLOW_RUNTIME_DEPENDENCY_POLICY=enforce`.
- Support an optional `VULNFLOW_WHEELHOUSE` directory for explicit `--no-index --find-links` installation.
- Add non-serving install-only modes so external validation can execute the real launcher installation and dependency-attestation path.
- Extend the static dependency-lock contract and public regressions to cover all local launch entry points.

## Compatibility

- Application routes, database schema 46, API behavior, and stored data are unchanged.
- Python 3.12 and 3.13 remain supported.
- The direct dependency declaration `requirements.txt` remains the packaging input; local execution now consumes the complete reviewed lock.
