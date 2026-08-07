# Project integrity and scheduled operations

VulnFlow 72.0.18 applies integrity and scheduled-operation boundaries independently to every active project store.

## Startup behavior

At startup the application enumerates active projects, applies the current SQLite schema migration to each project database, and checks each project's:

- evidence-file registration and custody state;
- append-only audit-chain integrity;
- project database and storage initialization.

A failed project is marked `READ_ONLY`. Healthy projects continue through policy initialization, export reconciliation, rescoring, checkpoint creation, and normal lifecycle startup. One damaged customer database therefore does not make unrelated customer projects unavailable.

## Request and worker boundaries

The selected project's recovery state is attached to each request. Mutating HTTP methods are blocked only when that project is read-only, while project switching and integrity-repair operations remain available.

Background workers enumerate active project queues and skip read-only projects. Scheduled maintenance, pending-webhook delivery, and recovery-backup producers also fan out across active projects and record skipped or failed project IDs without aborting the remaining projects.

## Administrator workflow

From `관리자 메뉴 → 고객사·프로젝트`, an administrator can:

1. inspect the last integrity-check result and bounded reason summary;
2. re-run integrity verification for one project;
3. queue an immediate recovery bundle for a healthy project;
4. switch away from an isolated project and continue operating healthy projects.

If every project was read-only at startup, lifecycle tasks remain stopped. A successful administrator integrity recheck starts the lifecycle supervisor without requiring another process restart.

## Storage boundary

Each non-default project continues to use its own SQLite database, evidence directory, export directory, import-preview directory, and recovery-bundle directory. The default project remains in the original database and paths for backward-compatible upgrades.

## Limitations

- Integrity state is process-local and is rebuilt at startup or explicit recheck; it is not a distributed consensus signal.
- Recovery bundles remain local by default. Optional mounted external replication and isolated restore drills are described in [`44_RECOVERY_DRILLS_AND_EXTERNAL_BACKUPS.md`](44_RECOVERY_DRILLS_AND_EXTERNAL_BACKUPS.md).
- Scheduling remains single-host and does not provide high availability.
- Operating-system administrators can access all project directories.
