# VulnFlow 72.0.29 release notes

Date: 2026-08-03
SQLite schema: 46 (unchanged)

## Purpose

This release hardens runtime verification and SQLite backup publication. It does not add a customer-facing workflow or change the database schema.

## Fixed

- The bounded runtime soak now executes direct services inside an explicit project scope.
- The soak now overrides the complete control/project/storage layout instead of writing generated databases into the repository `data/` directory.
- Repeated soak runs no longer reuse stale control, project, webhook, or background-job state from earlier executions.
- SQLite backups are created in a private temporary file, integrity-checked, fsynced, and atomically published.
- A failed backup attempt leaves an existing valid destination unchanged and removes partial files.
- Backing up a database onto itself is rejected.

## Added

- `scripts/runtime_fault_rehearsal.py` for bounded concurrent writes, lock waiting, backup-under-write-load, failed-snapshot preservation, process-death rollback, restore, SQLite integrity, and audit-chain checks.
- `tests/test_runtime_fault_resilience_v88.py` with regression coverage for isolated soak paths and atomic backup behavior.
- Public documentation for runtime stability, container-equivalent deployment, and fault-resilience boundaries.

## Verification

- Public core regression tests: 370 passed in five bounded groups (`78 + 76 + 75 + 64 + 77`).
- Bounded runtime stability soak: 12/12 lifespans passed; 28/28 durable jobs succeeded; 16 HMAC webhook deliveries accepted; no lifecycle timeout; final WAL size 0.
- Runtime fault rehearsal: 15/15 checks passed.
- SQLite schema remains 46.

## Limits

- The runtime soak is bounded and is not a 24-hour production endurance test.
- Process death is injected inside an uncommitted SQLite transaction; host power loss and filesystem corruption are not simulated.
- The failed-backup scenario verifies atomic destination preservation but does not exhaust a real filesystem.
- Current Docker image build, public PKI, real SMTP/Jira, customer scanner files, and managed-browser E2E remain outside this workspace verification.
