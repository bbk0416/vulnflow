# VulnFlow 72.0.49 — Verified external-validation execution snapshot

Release date: 2026-08-04

SQLite schema: 46

## Purpose

72.0.48 verifies a requester-signed runner kit before execution, but the child
exchange process previously identified its source only by the SHA-256 of
`SHA256SUMS.txt`. A listed source file could change after the kit verification
step while the manifest file itself stayed unchanged. Direct `execute-request`
invocation had the same gap.

72.0.49 verifies every public-manifest file and executes the collector from a
private manifest-only snapshot. It also signs the pre/post verified source
identity into the returned response.

## Security and correctness changes

- Added `scripts/external_validation_source_attestation.py` to validate every
  listed file, reject linked or escaping paths, and calculate a stable verified
  tree identity.
- Made signed-request verification reject a source tree whose actual bytes no
  longer match the signed public manifest.
- Made `execute-request` copy only manifest-listed files into a private
  temporary snapshot and run the collector from that snapshot.
- Added pre- and post-execution source attestation and rejected any snapshot
  change before the operator response is signed.
- Added response format v2 with signed source-attestation mode and before/after
  identities.
- Kept detached post-hoc signing distinguishable from an execute-request
  pre/post attestation; detached signing cannot promote an otherwise complete
  result to `validation_passed=true`.
- Made the runner-kit wrapper create an outer verified snapshot before loading
  the child exchange process, then re-check that snapshot after execution.
- Excluded unlisted files such as a planted `sitecustomize.py` from both
  execution snapshots.
- Made the standalone 12-cycle soak flush its final evidence and exit deterministically after clean lifecycle/thread verification, avoiding interpreter-shutdown stalls after a completed PASS.

## Verification contract

The new v109 suite contains seven focused tests covering:

- file tampering with an unchanged `SHA256SUMS.txt`;
- manifest-only snapshot inventory;
- collector execution from a private snapshot;
- mutation of the snapshot during execution;
- manifested symbolic-link escape rejection;
- existing or source-nested snapshot output rejection;
- successful wrapper exit with a surviving descendant process, proving bounded process-group cleanup without stdout-pipe deadlock.

The public core contract increases from 566 to 573 tests. Three Chromium E2E
tests remain outside the core count.

## Trust limit

The snapshot protects against accidental mutation, unlisted source injection,
and normal same-host TOCTOU between verification and process launch. It does
not defend against a fully compromised operating-system administrator who can
alter process memory, the Python interpreter, dependencies, or operator private
key while validation is running.
