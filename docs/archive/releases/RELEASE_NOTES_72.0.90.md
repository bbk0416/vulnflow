# VulnFlow Free — Public Beta 72.0.90

72.0.90 is a **Greenbone/OpenVAS modern CSV Port/Protocol identity correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import runtime/data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

Current Greenbone/OpenVAS CSV exports use a `Port/Protocol` column for the affected endpoint. VulnFlow 72.0.89 only recognized the legacy `Port` header in its Greenbone CSV adapter. As a result, two valid rows for the same NVT/CVE and asset on `443/tcp` and `8443/tcp` lost their endpoint during normalization, collapsed to the same canonical component identity, and caused the import batch to fail as a duplicate canonical finding candidate.

72.0.90 accepts `Port/Protocol` as the modern Greenbone CSV endpoint header while preserving the existing `Port` alias. Concrete non-zero numeric endpoints continue to be appended to canonical component identity, and host-level values retain the backward-compatible component value. XML behavior is unchanged.

## Regression contract

One new end-to-end regression uses the modern `Port/Protocol` CSV header, verifies distinct `443/tcp` and `8443/tcp` component identities, applies both rows through `apply_import_batch()`, and confirms that both findings are inserted. The public suite is now 715 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 129).

## Compatibility

SQLite schema remains 46. Runtime and development dependency package pins are unchanged. The supported scanner connector set and feature-frozen Free Public Beta scope are unchanged.
