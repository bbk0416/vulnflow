# VulnFlow 72.0.55 — Acceptance checkpoint-series transfer bundles

VulnFlow 72.0.55 adds a deterministic requester-signed transfer bundle for moving an acceptance checkpoint series across an independent storage boundary.

A direct file copy can stop after an older generation and still leave a cryptographically valid checkpoint-series prefix. The new transfer statement signs the exact file inventory, series tree SHA-256, checkpoint count, and head identities. Verification rejects truncated archives, path traversal, special files, inventory changes, requester substitution, and signature changes.

`install-transfer` is monotonic and resumable. It never replaces an existing checkpoint. It adds only missing immutable generations on the same chain, accepts an exact retry as idempotent, and rejects stale or forked bundles before the installed series can move backward or branch.

Seven v115 regression tests cover deterministic packaging, private-key exclusion, empty-store installation, idempotent retry, interrupted-prefix resumption, stale rollback refusal, fork refusal, unsafe archive rejection, and signed-inventory tampering. The public core contract increases from 603 to 610 tests while SQLite schema 46 remains unchanged.
