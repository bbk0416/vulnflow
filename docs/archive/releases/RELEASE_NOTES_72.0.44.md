# VulnFlow 72.0.44 — Witness-signed recovery-journal key backup

Release date: 2026-08-04
SQLite schema: 46

## Fixed

- Replaced unsigned self-consistent journal-key backup format v1 with Ed25519 witness-signed format v2.
- Added a monotonic journal-key generation derived from the authenticated deployment audit chain.
- Bound key material, target, generation, audit checkpoint, witness identity, and signature into one canonical backup document.
- Required a pinned witness public key and an independently stored minimum witness receipt for restore.
- Rejected arbitrary replacement keys with recomputed fingerprints, metadata tampering, another witness key, unsigned v1 backups, and stale generation rollback.
- Detected legacy audit history that records a restored old key after a newer rotation.
- Preserved interrupted-recovery usability by evaluating policy against the journal's authenticated previous keyring and audit snapshot when live history is damaged.
- Added exact CLI coverage for witness inputs and generation-aware restore.

## Verification

- Public core regression contract: 515 tests in five bounded groups.
- Chromium browser E2E remains a separate three-test contract.
- New witness-signed journal-key backup attack contract: 12 tests.
- Focused witness, journal authentication, startup recovery, lifecycle, and v2 backup contract: 47 tests.
- SQLite schema remains 46.

## Operator action

Create a new v2 backup after upgrading. The backup command now requires `--witness-private-key`; restore requires both `--trusted-witness-public-key` and `--minimum-witness-receipt`. Unsigned v1 journal-key backups are intentionally not accepted.

## Limitations

The v2 backup still contains the raw symmetric journal key and must be stored on encrypted offline media. The trust model depends on protecting the Ed25519 witness private key and external minimum witness receipt outside the deployment host's rollback boundary.
