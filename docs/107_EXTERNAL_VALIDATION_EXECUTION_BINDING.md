# External validation execution and report binding

## Problem

A machine-readable report is not proof that the command which produced it completed successfully. In the previous collector, an expected report containing `passed=true` could dominate a later non-zero process exit. A missing or malformed mandatory report could also fall back to the process exit code. Those behaviors created a false-pass boundary in the validation infrastructure itself.

## v2 check contract

For a check with a mandatory JSON report, all of the following are required before `status=passed` is possible:

1. the child process starts and exits with code zero;
2. it does not time out;
3. the report path exists as a regular non-symlink file;
4. the report is a non-empty UTF-8 JSON object;
5. `status`, `passed`, and `available` do not contradict each other;
6. the report's normalized status is `passed`;
7. the aggregate stores the exact report SHA-256;
8. the execution log exists and its SHA-256 is stored.

A non-zero process exit always fails the check even when a report claims success. `blocked`, `unavailable`, `not-provided`, `insufficient`, and `needs-review` remain explicit non-passing states.

## Aggregate contract

The aggregate rejects:

- missing required checks;
- duplicate required check names;
- unsupported status values;
- `passed` fields that do not match status;
- an evidence-inconsistent check marked as passed.

`release` mode returns success only when every required check is uniquely present and passed.

## Safe evidence directory lifecycle

The collector writes `.vulnflow-external-validation-evidence` with its canonical creation path. A non-empty directory can be overwritten only when that marker is valid for the current path. This prevents an accidental command such as `--output-dir . --overwrite` from deleting a repository or unrelated operator directory.

The independent verifier accepts an evidence archive after relocation, but a relocated directory is not automatically considered collector-owned for future destructive overwrite.

## Scanner corpus boundary

Customer files are untrusted inputs. The collector:

- rejects symbolic links;
- limits supported-file count and total bytes;
- reads each file once, then hashes and parses the same byte string;
- counts unique SHA-256 contents to prevent duplicate corpus inflation;
- excludes filenames, paths, contents, and raw exception messages from evidence;
- records opaque IDs, suffixes, sizes, hashes, parser outcomes, and sanitized failure classes only.

## Independent verification

Run:

```bash
python scripts/verify_external_validation_evidence.py reports/external-validation
```

The verifier checks:

- recursive `SHA256SUMS.txt` inventory and hashes;
- symbolic-link absence;
- aggregate format and required-check contract;
- every report and execution-log digest;
- source version and schema;
- the source tree's public-manifest digest.

Use `--without-source-binding` only when verifying a detached archive without the exact source tree. That mode checks internal consistency but cannot prove which source produced the evidence.

## Trust limit

The directory and its SHA-256 manifest are not an external trust anchor. An attacker able to replace the entire evidence directory can replace the aggregate and manifest together. Use trusted artifact storage or separately signed archives when that threat is relevant.
