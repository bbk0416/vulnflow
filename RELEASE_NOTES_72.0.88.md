# VulnFlow Free — Public Beta 72.0.88

72.0.88 is a **Tenable/Nessus multi-port finding-identity correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import runtime/data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

Tenable `.nessus` exports can contain separate `ReportItem` elements when the same vulnerability is found on different ports of the same host. Earlier VulnFlow releases preserved the endpoint only in human-readable notes while using the plugin name alone as canonical component identity. Two valid rows such as the same plugin/CVE on `443/tcp` and `8443/tcp` therefore collapsed to the same canonical key and caused the import batch to fail as a duplicate canonical finding candidate.

72.0.88 appends the non-zero `port/protocol` endpoint to the Nessus component identity. Host-level `port=0` results keep the historical component value unchanged. This preserves distinct per-port finding instances without changing the generic ingestion or reconciliation algorithms.

## Regression contract

One new end-to-end regression parses a two-port `.nessus` fixture, verifies distinct component identities, applies the rows through `apply_import_batch()`, and confirms that both findings are inserted. The public suite is now 713 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 127).

## Compatibility

SQLite schema remains 46. Runtime and development dependency package pins are unchanged. The supported scanner connector set and feature-frozen Free Public Beta scope are unchanged.
