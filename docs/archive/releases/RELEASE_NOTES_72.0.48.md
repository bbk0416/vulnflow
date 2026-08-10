# VulnFlow 72.0.48 — Signed external validation runner kit

Release date: 2026-08-04

SQLite schema: 46

## Purpose

72.0.47 authenticates a retained request and a signed returned response, but the
source snapshot, request bundle, requester public key, and launch instructions
still had to be moved separately.  72.0.48 packages those inputs into one
requester-signed deterministic runner kit and verifies the archive before any
external execution.

## Security and correctness changes

- Added `scripts/external_validation_runner_kit.py` with create, verify, safe
  extract, extracted-directory verify, and verified run commands.
- Bound the exact public source snapshot, request bytes, requester public-key
  copy, launchers, and operator instructions through one payload manifest and a
  requester Ed25519 signature.
- Required a separately pinned requester public key; the embedded key and
  verifier are never treated as trust anchors.
- Added one request-ID-derived ZIP root, normalized timestamps and modes, exact
  inventory checks, and deterministic byte-for-byte output for identical
  inputs.
- Rejected path traversal, multi-root or duplicate entries, links and special
  files, oversized expansion, linked source components, expired requests,
  mismatched source identity, wrong keys, root renaming, and payload-manifest
  recomputation after tampering.
- Required output ZIPs to be new and outside source, request, and key inputs.
- Required execution outputs to remain outside the extracted runner kit and
  re-verified the complete directory before launching the v37 collector.

## Verification contract

The new v108 suite contains fourteen attack and round-trip tests covering:

- deterministic archive reproduction and private-key exclusion;
- safe extraction and executable launcher mode;
- payload modification and recomputed-manifest attacks;
- wrong requester keys and mismatched private/public key pairs;
- traversal and special-file ZIP members;
- archive-root/request-ID binding;
- request expiry versus audit-only verification;
- output overlap and existing-output refusal;
- source symlink escape rejection;
- expanded-size limits;
- verification before child-process invocation.

The public core contract increases from 552 to 566 tests.  Three Chromium E2E
tests remain outside the core count.

## Operational limits

The runner kit makes transfer reproducible and authenticated.  It does not
supply unavailable Docker, Chromium, an exact dependency wheelhouse, or an
authorized customer scanner corpus, and it does not attest that the external
operator host is uncompromised.
