# Runtime fault resilience

VulnFlow 72.0.29 keeps SQLite schema 46 and strengthens the release verification and backup publication boundaries. This work does not add a customer workflow or claim high availability.

## Release-soak isolation

`scripts/runtime_stability_soak.py` now supplies a complete disposable runtime layout:

- control database
- default project database
- project storage folders
- coordination database
- import previews, exports, evidence, recovery, and external-backup roots
- copied synthetic sample files

The soak never falls back to the repository `data/` directory. Direct service calls execute inside an explicit `ProjectSelection`, matching the fail-closed project path contract introduced in 72.0.26.

Run the bounded lifecycle profile with:

```bash
python scripts/runtime_stability_soak.py --iterations 12
```

The release profile repeats twelve complete FastAPI lifespans while checking background jobs, HMAC webhook delivery, maintenance, backup validation, audit integrity, WAL truncation, thread reclamation, and bounded memory growth.

## Atomic SQLite snapshots

`backup_database()` no longer writes directly to the published destination. It now:

1. rejects source/destination aliases;
2. writes to a private temporary file in the destination directory;
3. uses the SQLite backup API;
4. runs `PRAGMA integrity_check` on the completed snapshot;
5. fsyncs the snapshot;
6. atomically replaces the destination;
7. removes the temporary file on every failure path.

A failed source read or interrupted snapshot therefore cannot replace a previous valid backup with a partial database.

## Fault-injection rehearsal

Run:

```bash
python scripts/runtime_fault_rehearsal.py
```

The bounded rehearsal exercises disposable data only and verifies:

- simultaneous finding writes and audit-chain serialization;
- a writer waiting behind a held `BEGIN IMMEDIATE` lock;
- a validated backup while writes continue;
- preservation of a previous backup when a later snapshot fails;
- removal of partial backup files;
- rollback after a child process exits inside an uncommitted transaction;
- restore into a separate database;
- final SQLite and audit-chain integrity.

## Interpretation limits

This is not a 24-hour soak, filesystem power-loss test, real disk-full test, multi-host cluster test, or production SLA. It does not simulate kernel panic, storage-controller failure, network filesystems, or corrupt sectors. The application remains a single-host SQLite product unless a different supported deployment architecture is introduced and validated.
