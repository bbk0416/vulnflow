# 72.0.12 Submission Stabilization

This release adds no new vulnerability-management domain capability. It corrects submission-facing consistency and quality gaps found during an independent whole-project review.

## Canonical version presentation

- The web header reads `CURRENT_APP_VERSION` through a Jinja global.
- The OSV client User-Agent uses the same application version.
- Dependency lock headers, test summaries, and release metadata are checked by `submission_readiness_smoke.py`.

## Evidence baseline semantics

The built-in scanner detects the EICAR test marker only. A non-detection is stored as `BASELINE_ONLY`, not `CLEAN`. Download and verification approval require either:

- `CLEAN` from the configured external scanner, or
- an explicit administrator `WAIVED` decision with a recorded reason.

Historical `builtin-baseline` rows incorrectly marked `CLEAN` are reclassified during database initialization.

## Test and coverage evidence

- The complete pytest inventory is recorded in `reports/full_pytest_verification.txt`.
- Application line coverage is measured by `scripts/coverage_verification.py`.
- The release floor is 75% line coverage.
- The scheduled/manual `full-release` GitHub Actions workflow runs full release verification and coverage separately from the fast push/pull-request workflow.

Coverage is a regression indicator, not proof that all security properties or operational conditions are tested.
