# Bounded runtime stability soak

The public release soak is implemented by `scripts/runtime_stability_soak.py`.

It runs complete application startup and shutdown cycles against one disposable, persistent project store. Each cycle checks liveness and readiness, queues HMAC webhook delivery, runs scoring work, periodically runs SQLite maintenance, and waits for durable jobs to finish. The final phase validates a SQLite backup, the audit chain, WAL truncation, resource shutdown, and bounded allocation growth.

The runtime tree is fully isolated below a temporary directory. No generated control database, project database, evidence directory, backup, or split-storage marker may be written under the repository `data/` directory.

Release command:

```bash
python scripts/runtime_stability_soak.py --iterations 12
```

A successful report is written to:

```text
reports/runtime_stability_soak_verification.txt
reports/runtime_stability_soak_verification.json
```

This is a bounded release check rather than a long-duration production endurance test.
