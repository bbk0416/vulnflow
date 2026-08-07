# VulnFlow 72.0.15

This release adds a guided scanner-result import workflow without removing the existing direct CSV automation endpoint.

## Supported input

- Nessus `.nessus` XML exports
- OpenVAS/Greenbone CSV exports
- OpenVAS/Greenbone XML reports
- Generic CSV, including UTF-8 and common Korean encodings
- Excel `.xlsx` workbooks

## Guided workflow

1. Upload a supported file.
2. Review the detected format, source columns, normalized preview, and validation summary.
3. Accept the suggested field mapping or correct it explicitly.
4. Download row-level errors when source data needs correction.
5. Apply the validated rows.

A source row containing multiple CVE identifiers is expanded into separate findings. Incremental imports may explicitly apply valid rows only. Full snapshots never allow partial application because skipped rows could make existing findings appear absent and incorrectly reconcile their lifecycle.

## Security and storage boundaries

- Preview sessions are bound to the authenticated actor and expire after a bounded TTL.
- Temporary uploads are stored outside public static paths with restricted file permissions.
- XML containing DTD or entity declarations is rejected.
- XLSX uploads receive ZIP-entry and expanded-size preflight checks before workbook parsing.
- Uploaded filenames are sanitized and parser failures are returned as bounded validation errors.
- Applied or expired preview files are deleted.

## Compatibility

The existing `POST /upload/findings` canonical CSV endpoint remains available for existing automation clients. The guided browser workflow uses separate preview, recheck, error-export, and apply endpoints. SQLite schema remains at version 41.

## Verification

The public core regression suite contains 273 passing tests, including 9 import-wizard tests covering Korean CSV, XLSX, Nessus, OpenVAS CSV/XML, actor-bound preview sessions, error export, incremental valid-row application, and full-snapshot safety. Browser E2E remains present but is not claimed as executed in this workspace because managed Chromium blocks loopback navigation. Ruff, Bandit, pip-audit, Docker rebuild, and vendor-certified parser validation were not completed here.
