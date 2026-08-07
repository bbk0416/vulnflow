# Customer and project isolation

VulnFlow 72.0.25 stores control-plane records and every project, including the default project, in separate SQLite databases and storage trees.

## Layout

```text
data/
├─ control.db                  # users, sessions, project registry, memberships
├─ vulnflow.db                 # retained legacy migration source; never restored as a project
└─ projects/
   ├─ default/
   │  ├─ vulnflow.db
   │  ├─ evidence/
   │  ├─ exports/
   │  ├─ import-previews/
   │  └─ backups/recovery/
   └─ <project-id>/
      ├─ vulnflow.db
      ├─ evidence/
      ├─ exports/
      ├─ import-previews/
      └─ backups/recovery/
```

On first 72.0.25 startup, the legacy `data/vulnflow.db` is retained and copied through SQLite's backup API into `control.db` and `projects/default/vulnflow.db`. The split targets are then migrated normally. Existing evidence, exports, import previews, and recovery bundles are copied once to the default-project tree. The legacy source is not deleted automatically.

## Authorization

Browser sessions may select only projects assigned through `project_memberships`. Administrators can access all active projects and manage assignments. Bearer tokens accept an optional project scope:

```json
{
  "scanner-ci": {
    "token": "replace-with-a-long-random-token",
    "role": "operator",
    "projects": ["default", "customer-a-1234abcd"]
  }
}
```

`"projects": "*"` grants access to all active projects. Omitting `projects` intentionally limits the token to `default` for backward-compatible least privilege. API clients choose a project with `X-VulnFlow-Project`.

## Operational boundaries

- The control database contains accounts, sessions, the project registry, memberships, and control-plane audit records only.
- Every project, including `default`, has its own findings, assets, jobs, evidence, exports, import previews, and recovery bundles.
- Recovery format v2 binds each bundle to `project_id` and `database_role=project-data`; a bundle for another project is rejected before restore.
- The background worker scans all active project queues.
- Disabling a project prevents new HTTP selection but does not delete its files.
- Project deletion is intentionally not exposed in this release.
- VulnFlow 72.0.18 verifies startup integrity and fans scheduled maintenance, webhook delivery, and recovery backups out independently across active projects; see [Project integrity and scheduled operations](43_PROJECT_INTEGRITY_AND_SCHEDULED_OPERATIONS.md).
- Optional external copies and isolated restore drills preserve the same project boundary; see [Recovery drills and external backup retention](44_RECOVERY_DRILLS_AND_EXTERNAL_BACKUPS.md).

This design reduces accidental cross-customer mixing on one host. It is not a hardened public multi-tenant SaaS boundary and does not protect against an operating-system administrator who can read all project directories.
