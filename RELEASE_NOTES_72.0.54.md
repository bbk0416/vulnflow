# VulnFlow 72.0.54 — Acceptance checkpoint series

VulnFlow 72.0.54 replaces manual selection of independent minimum-checkpoint files with an optional append-only checkpoint series. Each requester-signed checkpoint records a contiguous generation, the previous checkpoint file SHA-256, and a strictly increasing ledger receipt count.

`append-checkpoint-series` verifies that the current acceptance ledger extends the latest series head before publishing the next checkpoint. `verify-ledger` and `accept-response` can use `--minimum-checkpoint-series-dir`, which automatically applies the latest valid series checkpoint rather than trusting a manually selected stale checkpoint file.

Six v114 regression tests cover monotonic series append, latest-head rollback refusal, divergent-ledger advancement refusal, chain tampering, duplicate checkpoint refusal, and requester/inventory isolation. The public core contract increases from 597 to 603 tests while SQLite schema 46 remains unchanged.
