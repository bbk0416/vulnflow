# VulnFlow 72.0.46 — External validation execution binding

Release date: 2026-08-04  
SQLite schema: 46

## Purpose

72.0.45 separated genuine passes from blocked, unavailable, and missing external checks. 72.0.46 hardens the collector itself so a child process, malformed report, unsafe output path, or untrusted scanner directory cannot manufacture or corrupt that evidence.

## Security and correctness changes

- A JSON-backed check passes only when the child exits zero, the mandatory report exists, it is a non-empty UTF-8 JSON object, its status contract is internally consistent, and its exact SHA-256 is recorded.
- A report that says `passed=true` after a non-zero child exit is failed. Missing, invalid, contradictory, linked, or unreadable reports are also failed.
- Execution logs receive their own SHA-256 and are bound into the aggregate check record.
- Duplicate required check names, inconsistent `status`/`passed` fields, and unsupported terminal statuses invalidate the aggregate.
- Destructive `--overwrite` is permitted only for a directory previously created by the collector with a path-bound ownership marker. Repository roots, filesystem roots, and symbolic-link outputs are rejected.
- The evidence manifest now covers nested files recursively and rejects symbolic links.
- Customer scanner files are read once for both parsing and hashing. Symbolic links, excessive file counts, and excessive aggregate bytes are rejected.
- Scanner failures expose only opaque IDs, suffixes, stable error codes, and exception class names; original filenames and parser exception text are not copied into evidence.
- `scripts/verify_external_validation_evidence.py` independently verifies inventory hashes, report/log digests, aggregate contracts, version, schema, and public-manifest source identity.

## Verification contract

The focused v105/v106 suite covers:

- child exit/report mismatch;
- missing and malformed reports;
- contradictory report status;
- report digest binding;
- duplicate and inconsistent aggregate checks;
- unowned overwrite and symbolic-link output rejection;
- scanner symlink, privacy, file-count, and byte-count boundaries;
- valid, relocated, and tampered evidence directory verification;
- recursive manifest inventory.

The public core contract increases from 525 to 539 tests. The three Chromium E2E tests remain separate from the core count.

## Operational limits

This release verifies internal evidence consistency; it does not add an external signature or immutable timestamp. Evidence still requires trusted transport, independently signed packaging, or an external artifact service when adversarial replacement of the whole directory is in scope.
