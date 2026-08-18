# VulnFlow Free — Public Beta 72.0.91

72.0.91 is a **Greenbone/OpenVAS Customizable CSV schema-compatibility and endpoint-identity correctness patch** on the feature-frozen 72.0.72 line. It fixes independently reproduced scanner-import compatibility/data-integrity defects without changing SQLite schema 46 or dependency package pins.

## Fixed

Current Greenbone/OpenVAS Customizable CSV Results can expose endpoint identity as separate `Port` and `Port Protocol` columns and identify the vulnerability test with `VT Name`. VulnFlow 72.0.90 recognized combined `Port/Protocol` and legacy `NVT Name`, but it did not merge a separate protocol column into the canonical endpoint and did not recognize `VT Name` for scanner auto-detection/product naming.

As a result, two valid findings for the same asset, CVE, vulnerability test and numeric port on different protocols such as `443/tcp` and `443/udp` normalized to the same `[443]` component and the import batch was rejected as duplicate canonical finding candidates. A current `VT Name` CSV could also fall back to generic CSV handling or lose its vulnerability-test name.

72.0.91 combines a numeric `Port` with `Port Protocol` before endpoint identity normalization and recognizes `VT Name` as a Greenbone/OpenVAS vulnerability-name header. Existing combined `Port/Protocol`, legacy `NVT Name`/`Port`, XML `<port>` behavior, and host-level markers remain backward compatible.

## Regression contract

One new end-to-end regression uses `Port`, `Port Protocol`, `VT Name`, and `CVEs`, relies on automatic scanner detection, verifies `443/tcp` and `443/udp` component identities, applies both rows through `apply_import_batch()`, and confirms that both findings are inserted. The public suite is now 716 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 130).

## Compatibility

SQLite schema remains 46. Runtime and development dependency package pins are unchanged. The supported scanner connector set and feature-frozen Free Public Beta scope are unchanged.
