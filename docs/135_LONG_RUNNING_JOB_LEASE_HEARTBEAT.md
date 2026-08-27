# Long-running background-job lease heartbeat

P0-04 dynamic probing proved that a generic RUNNING background job could outlive
its lease while the worker awaited a blocking asyncio.to_thread call. Another
worker could then reclaim the same job, creating duplicate-execution risk.

The generic worker now periodically renews the existing durable job lease while
blocking execution is active. Lease ownership remains enforced by
heartbeat_background_job; lease loss fails closed with ConcurrencyError.

No table, migration, schema-version, job-type, or release-version change is
introduced. P0-04 also verified import rollback, observation lifecycle, a
synthetic 2,000-row import, idempotent replay, and SQLite contention retry
classification.
