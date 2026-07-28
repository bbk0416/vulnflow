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

The screenshot set can be recreated from synthetic data with:

```bash
pip install -r requirements-e2e.txt
python -m playwright install chromium
python scripts/capture_public_screenshots.py
```

The capture is repeatable in workflow and content, but image bytes are not claimed to be deterministic because timestamps and runtime identifiers can be rendered by the application.
