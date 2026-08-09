# VulnFlow 72.0.52 — Requester acceptance ledger

SQLite schema remains 46.

This release closes a replay and equivocation boundary after signed external
validation response verification.  Earlier releases authenticated the exact
challenge, source, evidence, and authorized operator, but the detached verifier
was stateless.  The same valid response could therefore be presented repeatedly,
and two different valid operator responses for one request could each pass when
verified independently.

72.0.52 adds a requester-signed, hash-chained acceptance ledger.  The first
accepted response for a request produces one receipt bound to the exact response
tree, request bytes, operator identity, source-attestation result, and product
validation result.  Re-presenting the same tree is rejected as replay.  A second
different tree for the same request is rejected as operator equivocation.

The ledger uses sequential single-file receipt envelopes, Ed25519 requester
signatures, previous-receipt SHA-256 chaining, exact inventory checks, and
exclusive publication of each sequence.  It stores no private key material.

Six v112 regression tests cover first acceptance, replay rejection, conflicting
response rejection, receipt tampering, requester-key substitution, and unexpected
ledger entries.  The public core contract increases from 585 to 591 tests while
SQLite schema 46 remains unchanged.
