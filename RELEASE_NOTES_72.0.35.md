# VulnFlow 72.0.35 release notes

VulnFlow 72.0.35 keeps SQLite schema 46 and hardens the signed offline
deployment bootstrap against destructive replacement and archive resource
exhaustion.

## Fixed

- `--force` no longer deletes the current deployment before the candidate has
  passed signed-distribution, runtime-snapshot, installation, service,
  persistence, SQLite-integrity, and schema checks.
- A candidate is built in a mode-0700 sibling staging directory and published
  only by same-filesystem rename.
- Existing deployments are retained in a hidden sibling previous directory.
- Post-rename health, authentication, persistence, shutdown, integrity, and
  schema failures restore the previous deployment automatically.
- Final deployment-report publication failure also rolls back activation.
- Fresh-install failure leaves no partial target.
- Absolute staging paths in the runtime configuration and launchers are
  rewritten to the final deployment target before activation verification.
- Root, symbolic-link, and non-directory deployment targets are rejected.

## Archive limits

- Release-kit ZIP entry count, individual size, total uncompressed size, and
  compression ratio are bounded.
- Duplicate, encrypted, symbolic-link, unsupported-type, and declared-size
  mismatch entries are rejected.
- Runtime snapshot member count and total uncompressed content are bounded
  before restore.

## Verification

- Public core regression contract: 431 tests in five bounded groups.
- New atomic activation and archive-boundary tests: 18.
- Signed offline deployment rehearsal contract: 27 checks, including fresh
  installation and forced replacement when a verified runtime snapshot is
  available.
- SQLite schema remains 46.

## Limits

- `--force` is a fresh replacement, not an in-place data migration.
- The old deployment is retained rather than automatically deleted; operators
  must apply an explicit retention policy after acceptance.
- Full signed-kit execution still requires a matching Linux CPython runtime
  snapshot. The current preparation environment cannot generate that snapshot
  because its installed packages do not match the production lock.
- Docker, Chromium acceptance, external services, and customer scanner files
  remain outside this release's locally completed evidence.
