# VulnFlow 72.0.40 release notes

VulnFlow 72.0.40 keeps SQLite schema 46 and adds a consistent, externally
witnessed recovery bundle for the offline deployment-history keyring and audit
log.

## Fixed

- Demonstrated that the previous key-only backup could not recover a lost or
  mismatched keyring and audit log as one point-in-time unit.
- Added a private recovery ZIP containing the keyring, audit chain, witness
  receipt, pinned public-key copy, manifest, and per-member SHA-256 inventory.
- Required an operator-supplied trusted public key and minimum external witness
  during verification and restore; bundles older than that witness are rejected.
- Rejected a recovery bundle older than a still-valid local audit history to
  prevent an accidental local rollback.
- Added isolated candidate verification against the keyring checkpoint, complete
  audit chain, witness prefix, and all currently retained deployment seals.
- Added a private rollback journal so an interrupted two-file restore is
  automatically returned to the previous keyring and audit pair.
- Removed an unaudited output bundle when creation succeeds on disk but the
  corresponding history audit event cannot be committed.
- Added the recovery module as a mandatory signed release-kit artifact and
  verified the management CLI outside the source tree.

## Verification

- Public core regression contract: 476 tests.
- Chromium E2E contract: 3 tests, still separate from the core suite.
- New history-recovery tests: 9.
- SQLite schema remains 46.

## Operational warning

The recovery bundle contains unencrypted history HMAC keys and must be stored
on encrypted offline media. Restore must be run with the service stopped and
requires a trusted witness public key plus an externally retained minimum
witness receipt. The bundle is not a substitute for retaining those external
trust anchors outside the deployment host.
