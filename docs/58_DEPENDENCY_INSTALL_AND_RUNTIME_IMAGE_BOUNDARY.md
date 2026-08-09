# Dependency install and runtime image boundary

VulnFlow 72.0.33 keeps SQLite schema 46 and separates three claims that were
previously easy to conflate:

1. the source dependency files are internally consistent,
2. the active interpreter happens to contain matching packages, and
3. a clean machine can download the complete pinned artifact set and reinstall
   it without consulting a package index.

Only the third claim demonstrates a repeatable fresh installation. Exact
version pins without downloaded artifact hashes do not prove that boundary.

## Clean wheelhouse rehearsal

Public CI now runs:

```bash
python scripts/dependency_wheelhouse_rehearsal.py \
  --json-output reports/dependency_wheelhouse_rehearsal.json
```

The rehearsal:

1. downloads every active package from `requirements-dev.lock` as a wheel,
2. records each filename, byte size, and SHA-256,
3. creates an empty virtual environment,
4. installs only from the downloaded wheelhouse with `--no-index`,
5. compares installed versions with the exact locks,
6. imports the application from source, and
7. runs focused HTTP and distribution-boundary tests.

The generated JSON report is retained as a GitHub Actions artifact even when
the strict job fails, so the downloaded filenames, sizes, hashes, and failing
phase remain reviewable. The generated hashes describe the artifacts fetched
by that specific CI run. They are evidence, not a committed cross-platform
hash lock. A compromised
upstream index before the CI run remains outside this control. Producing a
reviewed multi-platform `--require-hashes` lock remains future work.

A restricted workstation may record an unavailable package index with:

```bash
python scripts/dependency_wheelhouse_rehearsal.py \
  --allow-index-unavailable \
  --json-output reports/dependency_wheelhouse_rehearsal.json
```

That exit path is explicitly **not a pass** and is forbidden in public CI.

## Static versus installed dependency checks

Use the source-only check when the active interpreter is intentionally not the
release environment:

```bash
python scripts/dependency_lock_smoke.py --static-only
```

The normal CI command still compares the installed environment:

```bash
python scripts/dependency_lock_smoke.py
```

A static PASS does not imply that the current machine can install or run the
locked versions.

## Runtime dependency reduction

The application no longer imports Requests. Requests remains a development and
rehearsal dependency because deployment probes use it, but it is removed from:

- `requirements.txt`,
- `requirements.lock`,
- packaged application dependencies, and
- the runtime CycloneDX dependency set.

Its Requests-only transitive packages are also removed from the runtime lock.
This reduces the deployed dependency surface while preserving source-tree
rehearsals through `requirements-dev.lock`.

## Production image script boundary

The Docker image no longer copies the entire `scripts/` directory. It includes
only the reviewed offline administration commands needed to:

- prepare split storage,
- manage users,
- back up or restore the control database, and
- generate or verify integrity proof keys.

Browser automation, release tooling, scanner collection, network rehearsals,
quality gates, and soak tools remain outside the production image.

## Browser-independent workflow contract

Chromium remains the acceptance authority for actual browser behavior. The
core suite now additionally performs server-rendered workflow E2E checks for:

- dashboard-to-finding workflow updates,
- import preview, apply, and search, and
- operator risk-acceptance request followed by approver decision.

These checks execute real HTTP forms, CSRF validation, role separation, and
rendered selector contracts through Starlette TestClient. They do not validate
layout, JavaScript, browser security policy, or visual accessibility.

## Limits

- The preparation workspace could not reach public PyPI through pip and its
  configured internal mirror did not contain the locked FastAPI release. The
  clean wheelhouse installation therefore was not completed locally.
- Official PyPI project pages were checked separately to confirm that the main
  pinned releases exist, but this does not replace a pip installation.
- The local Chromium policy still returns `ERR_BLOCKED_BY_ADMINISTRATOR` before
  application assertions. Browser E2E remains a mandatory GitHub Actions job.
- Docker build and production Compose execution still require the separate
  Docker CI gate.
