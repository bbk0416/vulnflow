# VulnFlow 72.0.20 release notes

Released: 2026-08-02

## Summary

72.0.20 adds a repeatable pre-pilot production validation package. It verifies the schema-42 to schema-43 migration, reports scanner-file compatibility without importing customer data, provides read-only SMTP and Jira connection diagnostics, and adds a Docker upgrade rehearsal suitable for CI. SQLite schema remains 43.

## Added

- A frozen 72.0.18/schema-42 synthetic database fixture with SHA-256 metadata.
- Host and Docker upgrade rehearsal from schema 42 to the current schema.
- Read-only SMTP authentication diagnostics that never send email.
- Read-only Jira account and project authorization diagnostics that never create issues.
- Offline scanner compatibility JSON reports for Nessus, OpenVAS, CSV, and XLSX files.
- A five-file synthetic scanner fixture matrix with explicit expected outcomes.
- A combined `production_validation.py` entry point and public CI Docker rehearsal.
- Administrator UI controls for saved SMTP and Jira connection diagnostics.
- Downloadable compatibility reports from the import preview screen.

## Fixed

- Exported collaboration runtime settings that were missing from `settings.__all__`, which could prevent the integrations page from loading in some runtime contexts.
- Schema-43 backup validation now requires collaboration tables and rejects obsolete plaintext-secret columns.
- Jira diagnostics reject redirects rather than forwarding API-token authentication to another location.
- Dependency-lock smoke metadata now follows the current application version instead of a stale literal.

## Verification boundary

The included scanner corpus is synthetic and is not a certification of every Nessus or Greenbone export version. Real SMTP delivery, Jira issue creation, customer scanner files, and target-environment Docker, proxy, TLS, and storage behavior still require authorized pilot validation.

## Verification

- Public core regression suite: 319 tests in five bounded groups.
- Production-validation regression tests: 17.
- HTTP operational smoke: 125 checks.
- Architecture: 132 modules, 271 route decorators, zero internal import cycles.
- Host upgrade rehearsal and five-file synthetic scanner matrix: passed.

Docker was unavailable in the local workspace, so the Docker rehearsal is configured as a mandatory public CI job rather than claimed as locally passed. Chromium E2E remained blocked by the managed browser policy, and real SMTP/Jira endpoints and authorized customer scanner exports were not available.
