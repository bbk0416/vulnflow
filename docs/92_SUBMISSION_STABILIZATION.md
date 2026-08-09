# 72.0.15 Scanner Import Stabilization

This release adds the customer-facing scanner import wizard while preserving the existing canonical CSV automation endpoint and SQLite schema 41.

## Import boundary

- Nessus `.nessus`, OpenVAS/Greenbone CSV and XML, generic CSV, and XLSX are parsed into canonical finding rows.
- Browser uploads are staged in actor-bound preview sessions outside static paths.
- Operators review detected format, field mapping, normalized rows, and validation errors before any database mutation.
- Incremental imports may explicitly skip invalid rows; full snapshots fail closed when any row is invalid.

## Parser safety

- XML DTD and entity declarations are rejected.
- XLSX ZIP metadata is checked before workbook parsing.
- Upload size, normalized row count, field lengths, preview lifetime, and preview-session count are bounded.
- Temporary preview files use restricted permissions and are deleted after successful application or expiry.

## Release consistency

- `openpyxl` and `et_xmlfile` are pinned in runtime and development locks and recorded in the CycloneDX SBOM.
- `submission_readiness_smoke.py`, release metadata checks, dependency lock checks, and the public SHA-256 manifest remain required.
- The public core suite now contains 273 tests, including 9 scanner-import regression tests.

The parser fixtures are synthetic. Passing these tests does not claim vendor certification or compatibility with every scanner release and customized export template.
