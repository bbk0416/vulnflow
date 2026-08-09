# Locked local runtime installation

## Problem

The release, Docker, and external-validation paths used `requirements.lock`, but the ordinary Windows and Linux launchers installed `requirements.txt`. Although direct dependencies were pinned, transitive dependencies could differ from the versions used by the regression and runtime-soak evidence. The launchers also upgraded `pip` on every run and relied on shell activation to select the environment.

## Contract

The reviewed local launchers now:

1. require Python 3.12 or 3.13;
2. create `.venv` only when its interpreter is absent;
3. install `requirements.lock` through the absolute virtual-environment Python path;
4. never perform an implicit `pip` upgrade;
5. execute storage preparation, user administration, and Uvicorn through that same interpreter;
6. enable packaged runtime dependency enforcement unless explicitly overridden;
7. optionally install from `VULNFLOW_WHEELHOUSE` with `--no-index` and `--find-links`.
8. expose a non-serving install-only mode for direct external launcher validation.

`run_windows.bat` delegates to `run_windows.ps1`, leaving one reviewed Windows installation and startup implementation.

## Scope and limits

The lock pins package versions but does not embed distribution hashes. Supply-chain integrity for offline installation remains provided by the separately generated wheelhouse manifest and signed release/deployment artifacts. Network index availability and package retention are not guaranteed by this launcher contract.
