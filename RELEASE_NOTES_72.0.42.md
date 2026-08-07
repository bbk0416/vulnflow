# VulnFlow 72.0.42 — Authenticated recovery journal

Release date: 2026-08-04
SQLite schema: 46

## Fixed

- Recovery transaction journals now authenticate the canonical transaction manifest with HMAC-SHA-256 instead of relying only on an unkeyed size-and-SHA-256 inventory.
- Added a dedicated mode-0600, single-link, owner-checked recovery-journal key outside the transaction directory so keyring replacement does not move the journal trust anchor.
- Bound transaction state, target name, transaction ID, timestamps, backup-presence flags, and backup file hashes to the journal HMAC.
- Re-signed the journal whenever a prepared transaction becomes committed and fsynced the journal directory after each authenticated manifest write.
- Made startup preflight fail closed when the journal key is missing, replaced, linked, or has unsafe permissions.
- Reclassified the 72.0.40–72.0.41 v2 journal as integrity-inventoried but unauthenticated; it now requires explicit legacy recovery instead of automatic startup recovery.
- Changed invalid journal-manifest handling so forged backup metadata is rejected before any candidate history file is installed into the live paths.

## Verification

- Public core regression contract: 493 tests in five bounded groups.
- Chromium browser E2E remains a separate three-test contract.
- Authenticated journal regression contract: 9 tests.
- SQLite schema remains 46.

## Limitations

The local recovery-journal HMAC key is a host-side symmetric trust anchor. It detects corruption and journal rewriting by an actor that cannot read that key, but it does not resist root, the deployment account with read access to the key, or a coordinated rollback of the key and journal. Losing or replacing the key while a journal is pending blocks automatic startup recovery and requires manual investigation.
