# VulnFlow 72.0.57 — Windows path-contract completion

VulnFlow 72.0.57 keeps SQLite schema 46 and application runtime behavior unchanged. It fixes the final Windows public-regression failure discovered by the v46 external-validation run.

## Fixed

- Replaced hard-coded `projects/default/vulnflow.db` suffix comparisons with path-component comparisons that accept both `\` and `/`.
- Added an explicit regression covering Windows and POSIX path forms plus a negative project-name case.
- Updated the bounded public suite from 618 to 619 collected tests; group 3 grows from 123 to 124.

## Scope

This is a validation-contract correction. It does not change the database schema, generated runtime paths, authentication, storage layout, or deployment behavior.
