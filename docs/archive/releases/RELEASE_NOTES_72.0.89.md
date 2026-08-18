# VulnFlow Free — Public Beta 72.0.89

72.0.89 is a **Greenbone/OpenVAS multi-port finding-identity correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import runtime/data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

Greenbone/OpenVAS CSV and XML results can represent the same NVT/CVE on different network ports of one asset. Earlier VulnFlow releases preserved the Greenbone `Port`/`<port>` value only in human-readable notes while using the NVT name alone as canonical component identity. Two valid rows such as the same NVT/CVE on `443/tcp` and `8443/tcp` therefore collapsed to the same canonical key and caused the import batch to fail as a duplicate canonical finding candidate.

72.0.89 appends a concrete non-zero numeric endpoint to the Greenbone/OpenVAS component identity. Host-level values such as `0/tcp`, `general/tcp`, or an empty port keep the historical component value unchanged. This preserves distinct per-port finding instances without changing the generic ingestion or reconciliation algorithms.

## Regression contract

One new end-to-end regression covers both Greenbone XML and CSV multi-port inputs, verifies distinct component identities, applies the rows through `apply_import_batch()`, and confirms that both findings are inserted while host-level identity remains backward-compatible. The public suite is now 714 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 128).

## Compatibility

SQLite schema remains 46. Runtime and development dependency package pins are unchanged. The supported scanner connector set and feature-frozen Free Public Beta scope are unchanged.
