# VulnFlow 72.0.18 release notes

Released: 2026-08-02

## Summary

72.0.18 adds project-scoped recovery drills and optional replication of scheduled recovery bundles to a separately mounted filesystem. The SQLite schema remains 42.

## Added

- Optional `VULNFLOW_EXTERNAL_BACKUP_DIR` with a separate per-project retention count.
- Project-specific external paths under `<external-root>/<project-id>/`.
- Atomic external copy using a temporary file, fsync, rename, SHA-256 recomputation, and a `.zip.sha256` sidecar.
- External-copy verification before an external bundle can be used for a recovery drill.
- Administrator `격리 복원 리허설` actions for local and external project bundles.
- Isolated drill restore into temporary database and evidence stores without modifying live project data.
- Post-restore SQLite, audit-chain, and evidence-store verification.
- Persistent success and failure drill reports under each project's local recovery directory.
- Project UI summaries for local backups, external copies, and the latest drill result.
- A second Docker Compose backup volume separated from the operational data volume.
- Private filesystem permissions for external backup directories (`0700`) and copied bundles, SHA sidecars, and drill reports (`0600`) on POSIX systems.

## Changed

- A configured external-copy failure now fails the recovery background job instead of silently reporting complete protection.
- Recovery webhook payloads omit local and external server filesystem paths.
- Project recovery inventory is loaded only for the selected administrator project to avoid hashing every customer's stored bundles on each project-list request.
- Configuration audit warns when scheduled backups are enabled but no external location is configured.

## Security boundary

The SHA-256 sidecar detects corruption or later changes when the ZIP and sidecar are not both replaced. It is not an independent signature or immutable archive. Signed bundles, independent credentials, protected mounts, snapshots, offline copies, and organizational recovery procedures remain operator responsibilities.

## Verification

- Public core regression suite: 294 tests.
- New recovery-drill and external-retention regression tests: 6.
- HTTP operations smoke: 125 checks.
- Application architecture review: 124 Python modules, 262 FastAPI route decorators, 0 internal import cycles.
- SQLite schema: 42, unchanged.

Chromium E2E, Docker rebuild, external NAS behavior, removable media, object-storage retention, and long-duration recovery timing are not claimed by this release.
