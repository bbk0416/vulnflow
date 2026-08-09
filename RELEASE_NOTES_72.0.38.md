# VulnFlow 72.0.38 release notes

VulnFlow 72.0.38 keeps SQLite schema 46 and adds a bounded deployment-history
keyring, atomic key rotation, protected keyring backup/restore, and an external
authenticated audit chain for offline deployment operations.

## Fixed

- Replaced the single non-rotatable retained-history HMAC key with a versioned
  current/retired keyring while preserving v27 legacy-key compatibility.
- Made rotation reseal all managed retained deployments and reject seals made
  with retired keys.
- Restored the previous keyring, retained seals, and audit log when rotation
  fails partway through.
- Added mode-0600 keyring backup and verified restore with fail-closed checking
  of retained seals and the complete audit chain.
- Added a chained external JSONL audit log for activation, adoption, rollback,
  prune, key backup, key restore, and key rotation.
- Serialized audit append inside the audit file itself and fixed concurrent
  first-key creation producing transient empty or replaced key files.
- Added the keyring and audit modules as mandatory signed release-kit artifacts
  and verified standalone imports outside the source tree.

## Verification

- Public core regression contract: 459 tests.
- Chromium E2E contract: 3 tests, still separate from the core suite.
- New key lifecycle and audit tests: 12.
- SQLite schema remains 46.

## Operational warning

The exported keyring backup contains unencrypted secret HMAC key material. Store
it only on protected encrypted offline media. Removing retired keys invalidates
verification of older audit events and is therefore not automated.
