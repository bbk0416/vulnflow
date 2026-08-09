# External validation evidence gate

VulnFlow 72.0.45 stops treating missing infrastructure, managed browser policy, missing customer exports, and a genuine product failure as the same result. The external validation gate collects each state separately and never promotes a blocked or unavailable check to a pass.

## Purpose

The gate is an evidence collector for the remaining production-readiness work. It does not add a customer-facing feature and it does not certify the product. It combines seven independent contracts:

1. public source manifest verification;
2. clean dependency wheelhouse download and no-index reinstall;
3. production Docker Compose build, TLS proxy, restart, and volume persistence;
4. real Chromium workflow E2E;
5. the synthetic scanner regression matrix;
6. an operator-supplied customer scanner corpus;
7. the bounded runtime stability soak.

A result is one of `passed`, `failed`, `blocked`, `unavailable`, `not-provided`, `insufficient`, or `needs-review`. Only `passed` satisfies release mode.

## Collection mode

Use collection mode in a restricted workstation to preserve evidence even when a required external tool is absent:

```bash
python scripts/external_validation_gate.py \
  --mode collect \
  --output-dir reports/external-validation \
  --scanner-dir /secure/path/to/approved-anonymized-exports \
  --chromium /usr/bin/chromium
```

Collection mode exits successfully after writing the report, but the aggregate document keeps `passed: false` whenever any required check is incomplete. This mode is for diagnosis and evidence transfer, not release approval.

The output directory must be empty. Use `--overwrite` only when intentionally replacing an earlier evidence set.

## Release mode

Release mode returns non-zero unless every required check passes:

```bash
python scripts/external_validation_gate.py \
  --mode release \
  --output-dir reports/external-validation-release \
  --scanner-dir /secure/path/to/approved-anonymized-exports \
  --minimum-scanner-files 20 \
  --chromium /usr/bin/chromium
```

The customer corpus must contain at least 20 **unique file contents**. Copying the same export under different names does not satisfy the threshold. Files marked `REVIEW` remain `needs-review`; blocked or unreadable exports fail the check.

## Browser policy boundary

`run_browser_e2e.py` performs a managed-policy preflight. A policy such as:

```json
{"URLBlocklist": ["*"]}
```

prevents application navigation before any VulnFlow assertion runs. The runner records this as `blocked`, lists the policy files, and leaves `passed: false`. `--allow-environment-blocked` permits evidence collection only; the release gate still rejects the result.

## Customer-data privacy

Customer scanner contents are never copied into the evidence bundle. Filenames are also omitted because they can contain customer names, hostnames, dates, or project identifiers. The report stores only:

- an opaque per-run file ID;
- the file suffix;
- byte size;
- SHA-256 digest;
- detected format;
- source, importable, unsupported, and error counts;
- `READY`, `REVIEW`, or `BLOCKED` parser outcome.

The operator remains responsible for obtaining authorization and anonymizing the source exports before validation.

## Evidence integrity

The directory contains individual JSON reports and command logs, an aggregate `external-validation-report.json`, and a `SHA256SUMS.txt` covering every evidence file. The source identity includes the public source-manifest digest and records whether Git metadata was present.

The evidence manifest detects transfer corruption; it is not a digital signature. Store the bundle in an approved immutable or signed evidence system when stronger provenance is required.

## Limits

- The default 12-cycle runtime soak is bounded and is not a 24-hour endurance test.
- Synthetic scanner fixtures are parser regression contracts, not vendor certification.
- A local self-signed Compose rehearsal does not validate public DNS, ACME renewal, customer storage drivers, or external backup media.
- A passing bundle is not a penetration test, compliance certification, or production authorization.
