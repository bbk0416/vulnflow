# VulnFlow 72.0.45 — External validation evidence gate

Release date: 2026-08-04
SQLite schema: 46

## Changed

- Added one aggregate external validation collector for the public source manifest, clean wheelhouse reinstall, production Compose, Chromium workflows, synthetic scanner fixtures, an approved customer scanner corpus, and the bounded runtime soak.
- Added explicit `passed`, `failed`, `blocked`, `unavailable`, `not-provided`, `insufficient`, and `needs-review` states. A blocked or unavailable environment is never converted into a pass.
- Added collection mode for restricted workspaces and strict release mode that fails unless every required external contract passes.
- Added managed Chromium policy detection so `URLBlocklist: ["*"]` is recorded as an environment block before product assertions execute.
- Added privacy-preserving customer scanner evidence with opaque IDs, suffixes, byte sizes, SHA-256 hashes, and parser outcomes. Source contents and filenames are not copied.
- Required at least 20 unique scanner file contents by default, preventing duplicate copies from inflating the customer-validation corpus.
- Added a SHA-256 evidence manifest for all generated reports and logs.

## Verification contract

- Added 10 external-evidence boundary tests.
- Public core regression contract: 525 tests in five bounded groups.
- Chromium browser E2E remains a separate three-test contract.
- SQLite schema remains 46.

## Local preparation-workspace result

The v35 collector records the current workspace honestly:

- bounded runtime soak: passed;
- synthetic scanner matrix: passed;
- Docker Compose: unavailable because Docker is not installed;
- clean wheelhouse: unavailable because the configured package index lacks the exact lock;
- Chromium E2E: blocked by a managed all-URL block policy;
- approved customer scanner corpus: not provided.

These incomplete items are not claimed as passes and must be rerun in an authorized external validation environment.

## Limitations

The bounded soak is not a 24-hour endurance run. The gate produces integrity-hashed evidence but does not sign it and does not replace a penetration test, compliance assessment, or production approval process.
