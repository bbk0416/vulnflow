# Public quality gates

The public repository keeps the quality checks intentionally narrow and reproducible.

```bash
pip install -r requirements-quality.txt
python scripts/run_quality_gates.py
```

The command performs:

1. Python bytecode compilation for `app`, `scripts`, and `tests`.
2. A dependency-free static security-boundary audit that blocks new direct network clients, unsafe TLS disabling, raw sockets outside approved transports, shell execution, unapproved dynamic execution, unsafe temporary-file helpers, and unsafe deserialization imports.
3. Ruff fatal-error rules (`E9`, `F63`, `F7`, `F82`).
4. Bandit high-severity and high-confidence findings for application and script code.
5. `pip-audit` against the pinned runtime requirements.

`pip-audit` depends on an external advisory service. In a deliberately offline environment, run the remaining local checks with:

```bash
python scripts/run_quality_gates.py --skip-dependency-audit
```

Skipping the dependency audit is an explicit local exception, not a full quality-gate pass. GitHub Actions executes the complete command. The built-in boundary audit remains active even when Ruff, Bandit, or the advisory service is unavailable.

## Built-in network and execution boundary

The built-in audit owns a small allowlist of modules that may open outbound
connections. Webhook, Jira, OSV, KEV, and EPSS HTTP traffic must use the pinned
HTTP transport; SMTP must use the pinned SMTP transport. The audit also rejects
new `verify=False`, `ssl._create_unverified_context`, `shell=True`,
`tempfile.mktemp`, `pickle`, and `marshal` use. Existing router source isolation
uses `exec` in one explicitly reviewed owner and is not a general exemption.

Run it independently with:

```bash
python scripts/static_security_boundary_audit.py
```

A PASS means only that the checked syntactic boundaries were respected. It does
not prove business authorization, dependency safety, or absence of all SSRF and
code-execution paths.

## Dynamic dependency-injection boundary

The router modules listed in `pyproject.toml` under `tool.ruff.lint.per-file-ignores`
receive runtime symbols through `install_dependencies()`. Ruff cannot infer those
injected globals, so only `F821` is ignored for that explicit router set. All syntax
and invalid-control-flow checks remain enabled there, and undefined-name checks
remain enabled for the rest of the repository.

The application-context composition helpers use local structural `Protocol` types
instead of importing the concrete context class, preserving the zero-import-cycle
architecture boundary.

## Audited dependency baseline

The production runtime baseline pins FastAPI 0.140.9, Starlette 1.3.1,
python-multipart 0.0.31, and cryptography 50.0.0. Requests 2.33.0 is retained only
in the development lock for deployment and rehearsal tooling; application code
uses the reviewed pinned transports and the production image does not install
Requests or its dedicated transitive packages. The complete CI quality job remains
the acceptance authority.

Source consistency, the active interpreter, and a clean install are separate
claims. Run the source-only check when the current interpreter is intentionally
not the release environment:

```bash
python scripts/dependency_lock_smoke.py --static-only
```

Public CI additionally proves that the exact development lock can be downloaded
as wheels, hashed, installed into a new virtual environment without an index,
and used to import and smoke-test the application:

```bash
python scripts/dependency_wheelhouse_rehearsal.py \
  --json-output reports/dependency_wheelhouse_rehearsal.json
```

The JSON result is retained as a GitHub Actions artifact, including on failure.
The recorded SHA-256 values describe the artifacts fetched in that CI run. They
are not a committed cross-platform `--require-hashes` lock. `--allow-index-unavailable`
is a local diagnostic exit and is forbidden in the public CI gate.

The screenshot set can be recreated from synthetic data with:

```bash
pip install -r requirements-e2e.txt
python -m playwright install chromium
python scripts/capture_public_screenshots.py
```

The capture is repeatable in workflow and content, but image bytes are not claimed to be deterministic because timestamps and runtime identifiers can be rendered by the application.

## Release metadata consistency

`python scripts/version_consistency_smoke.py` verifies that `VERSION`, `pyproject.toml`, `CURRENT_APP_VERSION`, `CITATION.cff`, the default Docker image tag, lock headers, and both CycloneDX application references use the same version. Public CI runs this check before manifest verification.
