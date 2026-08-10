# VulnFlow 72.0.41 — Offline recovery startup preflight

Release date: 2026-08-03
SQLite schema: 46

## Fixed

- Recovery transaction journals now record the size and SHA-256 of the previous history keyring and audit log instead of trusting journal backup files blindly.
- A prepared journal is removed only after the restored keyring, full audit chain, and retained-deployment seals verify successfully.
- A committed journal is removed only after the live audit history and retained seals verify; invalid live state keeps the journal for investigation.
- Unsafe, overly permissive, foreign-owned, duplicate, or legacy journals fail closed.
- Signed offline installations now copy the reviewed management modules into a private runtime directory and execute a deployment-history preflight before every service start.
- One integrity-inventoried interrupted recovery is restored automatically under the deployment operation lock; ambiguous or legacy state blocks startup.
- Added explicit status and manual recovery commands, including a separate confirmation for legacy v30 journals.
- Shell launchers now quote deployment paths safely.

## Verification

- Public core regression contract: 484 tests in five bounded groups.
- Chromium browser E2E remains a separate three-test contract.
- SQLite schema remains 46.

## Limitations

The journal inventory uses SHA-256 for accidental corruption detection and relies on private directory and file permissions for its local trust boundary. It is not an external cryptographic witness. Legacy v30 journals have no file inventory and require explicit manual confirmation instead of automatic startup recovery.
