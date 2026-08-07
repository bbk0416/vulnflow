# VulnFlow 72.0.39 release notes

VulnFlow 72.0.39 keeps SQLite schema 46 and adds an external Ed25519 witness
checkpoint for the offline deployment-history audit chain.

## Fixed

- Demonstrated that restoring the local history keyring and audit file together
  to an older internally consistent snapshot was not detected by the v28 local
  checkpoint alone.
- Added signed witness receipts that anchor an audit sequence and entry hash
  outside the deployment host's local rollback boundary.
- Added verification that accepts newer local history while rejecting a local
  log that is shorter than or diverges from the witnessed prefix.
- Added fail-closed receipt target-name, trusted-public-key, signature, file
  type, size, and private-key permission checks.
- Fixed the deployment manager assuming every subcommand had `--target`, which
  broke the standalone witness-key generation CLI.
- Added the witness module as a mandatory signed release-kit artifact and
  verified standalone imports outside the source tree.

## Verification

- Public core regression contract: 467 tests.
- Chromium E2E contract: 3 tests, still separate from the core suite.
- New external witness tests: 8.
- SQLite schema remains 46.

## Operational warning

A witness receipt prevents coordinated local rollback only when the latest
receipt and trusted public key are stored outside the same administrative and
filesystem rollback boundary. The witness private key must remain offline or
on a separately administered signer.
