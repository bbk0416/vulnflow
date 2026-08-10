# VulnFlow 72.0.47 — Signed external validation exchange

Release date: 2026-08-04

SQLite schema: 46

## Purpose

72.0.46 made an individual evidence directory internally self-consistent, but
the directory remained unsigned.  An actor able to replace the entire evidence
tree could replace its manifest and aggregate together.  72.0.47 adds an
Ed25519-signed, expiring challenge-response exchange that binds external results
to a request retained by the reviewer and to a separately pinned runner key.

## Security and correctness changes

- Added `scripts/external_validation_exchange.py` with key generation, signed
  request creation, request verification, response signing, one-command request
  execution, and independent response verification.
- A request binds an unpredictable nonce, request ID, target, lifetime, exact
  public source identity, required check list, scanner minimum, and soak count.
- A runner refuses modified, expired, wrong-source, or differently scoped
  requests before running validation.
- A response binds the exact retained request, all evidence bytes, aggregate and
  evidence-manifest hashes, pass/completeness fields, runner label, and pinned
  operator-key fingerprint under an Ed25519 signature.
- Response verification requires the reviewer's retained request plus separately
  pinned requester and operator public keys.  An embedded key alone is never a
  trust anchor.
- Exchange integrity and product validation remain separate.  A signed
  `INCOMPLETE` result remains non-passing.
- Private key files must be regular non-symlink files and, on POSIX, mode 0600 or
  stricter.  Request, evidence, and response paths may not overlap.
- The independent evidence verifier now requires the expected report and
  execution record for each check and recomputes aggregate status from report
  content and child exit state.

## Verification contract

The focused v105-v107 suite covers:

- signed request round trip, expiry, source mismatch, tampering, and wrong key;
- signed incomplete and complete responses;
- wrong expected request, wrong runner key, payload and statement tampering;
- private-key permission and path-overlap boundaries;
- missing required reports and execution records;
- report-status versus aggregate-status mismatch;
- malformed operator identity without verifier crashes.

The public core contract increases from 539 to 552 tests.  The former oversized
third process is split into three bounded groups, producing seven non-overlapping
core processes.  Three Chromium E2E tests remain outside the core count.

## Operational limits

This release authenticates the validation exchange.  It does not make missing
Docker, blocked Chromium, absent customer files, or an unavailable exact
wheelhouse pass.  It also does not attest that the external runner host itself
was uncompromised.
