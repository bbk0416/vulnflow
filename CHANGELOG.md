# Changelog

This public changelog summarizes the portfolio-facing release line. It does not reproduce every internal verification iteration.

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
