# Public quality gates

The public repository keeps the quality checks intentionally narrow and reproducible.

```bash
pip install -r requirements-quality.txt
python scripts/run_quality_gates.py
```

The command performs:

1. Python bytecode compilation for `app`, `scripts`, and `tests`.
2. Ruff fatal-error rules (`E9`, `F63`, `F7`, `F82`).
3. Bandit high-severity and high-confidence findings for application and script code.
4. `pip-audit` against the pinned runtime requirements.

`pip-audit` depends on an external advisory service. In a deliberately offline environment, run the remaining local checks with:

```bash
python scripts/run_quality_gates.py --skip-dependency-audit
```

Skipping the dependency audit is an explicit local exception, not a full quality-gate pass. GitHub Actions executes the complete command.

## Dynamic dependency-injection boundary

`app/routers/trust.py` and `app/routers/trust_observability.py` receive their
runtime symbols through `install_dependencies()`. Ruff cannot infer those injected
globals, so only `F821` is ignored for those two files. All syntax, invalid control
flow, and undefined-name checks remain enabled for the rest of the repository.

The application-context composition helpers use local structural `Protocol` types
instead of importing the concrete context class, preserving the zero-import-cycle
architecture boundary.

## Audited dependency baseline

The public audit baseline pins FastAPI 0.140.9, Starlette 1.3.1,
python-multipart 0.0.31, cryptography 48.0.1, and Requests 2.33.0. These versions
are selected to clear the advisories affecting the previous public pins, including
PYSEC-2026-2275 reported against Requests 2.32.5; the complete CI quality job
remains the acceptance authority.

The screenshot set can be recreated from synthetic data with:

```bash
pip install -r requirements-e2e.txt
python -m playwright install chromium
python scripts/capture_public_screenshots.py
```

The capture is repeatable in workflow and content, but image bytes are not claimed to be deterministic because timestamps and runtime identifiers can be rendered by the application.

## Release metadata consistency

`python scripts/version_consistency_smoke.py` verifies that `VERSION`, `pyproject.toml`, `CURRENT_APP_VERSION`, `CITATION.cff`, the default Docker image tag, lock headers, and both CycloneDX application references use the same version. Public CI runs this check before manifest verification.
