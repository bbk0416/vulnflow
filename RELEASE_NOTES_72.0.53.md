# VulnFlow 72.0.53 — Acceptance ledger minimum checkpoint

SQLite schema remains 46.

This release closes a whole-ledger rollback boundary in the requester acceptance ledger. The 72.0.52 receipt signatures and hash chain detect modified or conflicting receipt contents, but an older valid prefix remains cryptographically valid when considered by itself. Replacing the complete ledger with that prefix could remove later acceptances and allow a removed request to be accepted again.

72.0.53 adds a requester-signed minimum checkpoint that binds the accepted receipt count, head receipt SHA-256, head request ID, and response-tree identity. Ledger verification and response acceptance can require an independently retained checkpoint. A ledger that is shorter than or diverges from that floor is rejected before any new receipt is published, while a valid extension beyond the checkpoint remains allowed.

Six v113 regression tests cover checkpoint creation and verification, valid-prefix rollback detection, append refusal after rollback, extension beyond a checkpoint, checkpoint tampering, and requester-key substitution. The public core contract increases from 591 to 597 tests while SQLite schema 46 remains unchanged.
