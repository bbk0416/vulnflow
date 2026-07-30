# Changelog

This public changelog summarizes the portfolio-facing release line. It does not reproduce every internal verification iteration.

## Unreleased maintenance — 2026-07-30

- replaces stale `.github/workflows/tests.yml` references with the actual public workflow path;
- makes the dependency-lock validator report a missing public workflow as a consistency issue instead of crashing;
- installs `requirements-dev.lock` in the core CI matrix and runs the dependency-lock smoke check;
- adds a public-scoped release-metadata check that respects the artifacts intentionally excluded from the public repository;
- adds regression coverage without changing application behavior or database schema; the public regression suite increases from 243 to 244 tests.

## 72.0.13 — 2026-07-29

Tag-alignment and metadata-consistency patch release.

- includes the CycloneDX dependency-root correction merged after `v72.0.12`;
- retains the 11/11 release-metadata consistency gate in public CI;
- aligns the repository version, package metadata, application version, Docker tag, citation, lock headers, and CycloneDX application references at `72.0.13`;
- changes no vulnerability-management workflow, database schema, authentication behavior, or Docker runtime behavior;
- keeps the original Windows Docker Desktop validation and its stated limitations as historical evidence.

## 72.0.12 — 2026-07-29

Docker-runtime and public-release maintenance.

- verified the shipped Dockerfile and docker-compose.yml on Windows Docker Desktop;
- confirmed readiness, non-root UID 10001, SQLite schema 40, synthetic API import, restart persistence, container recreation persistence, transactional SQLite backup, and restore into a new named volume;
- retained the 243-test public regression suite, three Chromium E2E flows, cross-platform CI matrix, Ruff fatal checks, Bandit high/high checks, and pip-audit gate;
- documented the validation boundary without claiming customer deployment, production SLA, 24-hour endurance, or Windows runtime-snapshot verification;
- changed only release metadata and public verification documentation after the runtime validation.


## Final public quality maintenance

- expanded the README into a three-step VM demonstration scenario with five repeatable synthetic-data screenshots;
- added a screenshot capture script that uses a temporary SQLite database and does not retain runtime data;
- added a dedicated CI quality job for Python compilation, Ruff fatal rules, Bandit high/high findings, and pip-audit;
- split the 397-line restore validation function into bounded schema-validation helpers without changing restore behavior;
- expanded the public regression suite from 240 to 243 tests.
- fixed the first PR quality run by adding structural context protocols and narrowly scoping Ruff F821 exceptions to the two runtime-injected trust routers;
- raised FastAPI, Starlette, python-multipart, and cryptography to patched dependency baselines before rerunning pip-audit.
- raised Requests from 2.32.5 to 2.33.0 after pip-audit identified PYSEC-2026-2275 in the prior runtime pin.

## Public browser workflow maintenance

- Added three Chromium E2E flows for finding workflow updates, CSV ingestion, and separated operator/approver risk acceptance.
- Added a dedicated Ubuntu/Python 3.13 Playwright CI job instead of multiplying browser downloads across the core OS/Python matrix.
- Added public readiness and regression checks that keep the browser workflow job present.

## Public UI focus maintenance

- Reduced the header to five primary navigation entry points while retaining all existing routes in grouped menus.
- Added a task-first dashboard for immediate findings, overdue work, verification, and active campaigns.
- Moved secondary metrics and advanced filters behind progressive disclosure to reduce first-screen density.
- Added public regression checks for the focused navigation and dashboard workflow.

## Public repository maintenance

- made architecture and submission-readiness checks self-contained in a clean public clone;
- added SHA-256 manifest verification to public CI;
- added Python 3.12 and 3.13 CI coverage with minimal token permissions;
- aligned helper-script Python requirements to 3.12;
- added Dependabot, line-ending policy, and CI status badge;
- shortened the public security-reporting policy and removed upload-only files.
- made every `with connect(...)` transaction close its SQLite handle deterministically, preventing Windows temporary-file locks across recovery, validation and snapshot exports;
- made the ClamAV adapter test cross-platform and converted executable-launch failures into explicit scanner errors;
- expanded public CI to Ubuntu and Windows on Python 3.12 and 3.13.

## 72.0.11 — 2026-07-27

Submission-stabilization release.

- unified user-visible version strings with the application version source;
- replaced the misleading built-in evidence result `CLEAN` with `BASELINE_ONLY`;
- required an explicit administrative exception before baseline-only evidence can be approved or downloaded;
- added submission-readiness checks and public CI maintenance paths;
- measured application line coverage at 79.96% with a 75% release threshold;
- excluded transient runtime databases and coverage data from source provenance fingerprints;
- prepared the public repository with synthetic data and 230 representative tests.

## 72.0.10 — 2026-07-26

- hardened single-host leader election with database-holder and fencing-token checks;
- changed cluster rehearsal to dynamic ports and verified process and instance identity;
- prevented stale local leader state from authorizing scheduled work;
- verified offline bootstrap, restart persistence, upgrade recovery, and cluster failover boundaries.

## 72.0.9 — 2026-07-26

- added a deterministic project ZIP and signed offline release-distribution index;
- added an independent verifier for packaged artifacts and provenance linkage.

## 72.0.8 — 2026-07-26

- added in-toto/SLSA-style release provenance and DSSE Ed25519 rehearsal signing;
- stabilized lifecycle soak cadence and bounded shutdown behavior.

## Earlier development

Earlier releases built the core finding, asset, prioritization, remediation, approval, evidence, audit, background-job, backup, recovery, SBOM, VEX, and OSV workflows. The public repository focuses on the current behavior rather than every historical internal package.

### Post-release metadata correction — 2026-07-29

- corrected the CycloneDX dependency root from `pkg:generic/vulnflow@72.0.8` to `pkg:generic/vulnflow@72.0.12`;
- added a release-metadata consistency gate for version, package, Docker, citation, lock-header, and SBOM references;
- retained application behavior and version `72.0.12`.

### Repository operations policy — 2026-07-30

- changed Dependabot version updates from ungrouped weekly pull requests to grouped monthly minor and patch updates;
- stopped automatic major-version proposals while preserving separate handling for security updates;
- aligned the support document with the repository's restricted public-support model;
- documented the frozen portfolio maintenance and release boundary;
- changed no application version, runtime dependency or VM workflow.

### Public maintenance hotfix follow-up — 2026-07-30

- made the public release-metadata check skip optional browser-test collection when the public release manifest is absent and `--collect-tests` was not requested;
- added regression coverage for forwarding the explicit collection flag into fallback manifest generation;
- changed no application behavior, database schema, VM workflow, or release version.
