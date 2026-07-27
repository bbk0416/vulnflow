# Asset Merge Scoped Rollback

VulnFlow 24.0 adds a constrained rollback path for asset merges. It does not restore the whole database. It restores only records captured in the immutable journal created immediately before the selected merge.

## Workflow

```text
asset merge transaction
→ pre-merge scoped snapshot
→ merge
→ post-merge guard snapshot and SHA-256
→ immutable rollback journal

operator rollback request
→ current guard recalculation
→ approver decision
→ one SQLite transaction restores the scoped snapshot
→ audit event records the rollback
```

## Journal scope

The pre-merge snapshot contains the two assets and merge-affected records:

- findings located on either asset
- scanner source records and finding observations
- campaign membership
- active reconciliation decisions
- asset identifiers
- identity candidates involving either asset

The post-merge guard additionally covers records that the merge itself does not rewrite but whose later change would make a local rollback unsafe:

- risk-acceptance requests
- remediation-verification requests
- evidence metadata and custody events
- SBOM finding links
- VEX statements

## Safety properties

- Only merges performed by 23.0 or later have a scoped rollback journal.
- The journal and rollback request core fields are protected by SQLite triggers.
- A rollback request cannot be created after any guarded record changes.
- Only one pending rollback request may exist for a merge.
- Operator requests and approver decisions are separated by RBAC.
- The approval transaction restores the snapshot and appends an audit event atomically.
- A completed rollback cannot be applied twice.
- Candidates created during the merge are not deleted; they are marked rejected so history remains visible.

## Intentional limits

- This is not arbitrary time travel and is not an alternative to recovery bundles.
- Audit events are append-only and are never removed by scoped rollback.
- Any post-merge change to affected assets, findings, approvals, evidence, SBOM links, or VEX blocks rollback.
- Merges performed before the journal schema was available require full recovery-bundle restore if reversal is necessary.
- The feature is designed for the local single-database deployment model.

## UI and API

```text
GET  /asset-merges/{merge_id}/rollback-impact
POST /asset-merges/{merge_id}/request-rollback
POST /asset-merge-rollback-requests/{rollback_request_id}/decision

GET  /api/v1/asset-merges/{merge_id}/rollback-impact
POST /api/v1/asset-merges/{merge_id}/rollback-requests
GET  /api/v1/asset-merge-rollback-requests
POST /api/v1/asset-merge-rollback-requests/{rollback_request_id}/decision
```
