# VulnFlow Free — Public Beta 72.0.82

72.0.82 is a **documentation/runtime-contract integrity patch** on the feature-frozen 72.0.72 line. It does not add product features, change schema 46, or change dependency package pins.

## Fixed

- Corrected stale public regression counts in `README.md` and `PUBLIC_SCOPE.md`.
- Corrected first-admin and initial database documentation to use the separated control DB (`data/control.db`) and default project DB (`data/projects/default/vulnflow.db`).
- Corrected browser-auth documentation: failed logins use a 300-second sliding window with username+client and client-wide limits; account-wide lockout is disabled.
- Added `scripts/documentation_consistency_smoke.py`, which derives the public regression contract, schema, and authentication defaults from executable source and fails closed when release-facing documentation drifts.
- Added the documentation consistency gate to every public core-test CI matrix job and to public submission-readiness checks.

## Regression coverage

Five v82 regressions verify the current contract and demonstrate fail-closed detection for stale test counts, stale 15-minute lockout language, stale first-admin DB paths, and missing CI gate wiring. The public suite is now 704 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 118).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Scanner parsers/connectors: unchanged
- Application workflows and product feature scope: unchanged
