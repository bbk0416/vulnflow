# Recovery drills and external backup retention

VulnFlow 72.0.18 adds project-scoped recovery drills and optional replication of completed recovery bundles to a separately mounted filesystem.

## Backup flow

A scheduled or administrator-queued `RECOVERY_BACKUP` job now performs these steps:

1. create the normal project recovery ZIP in the project's local recovery directory;
2. validate the bundle while creating it, including SQLite, audit-chain, evidence-manifest, and optional HMAC checks;
3. when `VULNFLOW_EXTERNAL_BACKUP_DIR` is configured, copy the completed ZIP to `<external-root>/<project-id>/`;
4. fsync and atomically rename the temporary copy;
5. recompute SHA-256 and write a matching `.zip.sha256` sidecar;
6. prune local and external copies using their independent retention counts.

An external-copy failure fails the background job instead of silently reporting a fully protected backup. The already-created local bundle remains available for diagnosis and retry.

## Configuration

```env
VULNFLOW_BACKUP_INTERVAL_HOURS=24
VULNFLOW_BACKUP_RETENTION_COUNT=10
VULNFLOW_EXTERNAL_BACKUP_DIR=/mnt/vulnflow-backups
VULNFLOW_EXTERNAL_BACKUP_RETENTION_COUNT=30
```

On Windows, the external root may be a separate drive or mounted share, for example `E:/VulnFlow-Backups`. On Linux it may be a separately mounted block device or NAS path. The application process must have create, write, rename, read, and delete permissions in that root. On POSIX systems, VulnFlow tightens each project backup and drill-report directory to `0700` and creates copied bundles, SHA sidecars, and drill reports with `0600`; mount-level ACLs and backup-agent credentials still remain operator responsibilities.

Docker Compose uses a second named volume at `/app/external-backups`. For meaningful disaster recovery, operators should replace that named volume with an independently protected bind mount, NAS mount, or backup-agent-managed location.

## Project isolation

External copies are stored under the project identifier:

```text
<external-root>/
├─ default/
│  ├─ vulnflow_recovery_<timestamp>.zip
│  └─ vulnflow_recovery_<timestamp>.zip.sha256
└─ customer-a-1234abcd/
   ├─ vulnflow_recovery_<timestamp>.zip
   └─ vulnflow_recovery_<timestamp>.zip.sha256
```

Retention is applied within each project directory. A project therefore cannot prune another project's copies.

## Isolated recovery drill

From `관리자 메뉴 → 고객사·프로젝트`, an administrator may run `격리 복원 리허설` against a local or external bundle. The drill does not replace the live project database.

It instead:

1. verifies the stored external sidecar when the source is external;
2. validates the recovery ZIP and optional signature requirement;
3. restores the database and evidence files into a temporary isolated directory;
4. applies supported database migrations through the normal restore path;
5. reruns SQLite validation, audit-chain verification, and evidence-store verification;
6. stores a bounded JSON report under the project's local `recovery/drills/` directory.

Successful and failed drills are both recorded. The report contains the source bundle hash, result, duration, schema and item counts, and bounded error information. Temporary restored data is deleted after the drill.

## Live restore boundary

A passing drill proves that the selected bundle can be restored by the current application under the tested local conditions. It does not automatically modify the live project. An actual restore remains an explicit administrator operation with the existing write barrier, active-job check, confirmation phrase, safety backup, and post-restore integrity recheck or restart.

## Security and operational limitations

- A SHA-256 sidecar detects accidental corruption and later file changes but is not an independent signature. Configure signed recovery bundles when authenticity matters.
- A second directory on the same physical disk is not off-host backup protection.
- The implementation targets mounted filesystems; it does not directly implement S3, Azure Blob, immutable object lock, tape, or WORM retention.
- Filesystem administrators can still replace both a ZIP and its sidecar. Independent access control, snapshots, backup-agent verification, and offline copies remain operator responsibilities.
- Drill success is point-in-time evidence, not a recovery-time objective, recovery-point objective, or availability SLA.
