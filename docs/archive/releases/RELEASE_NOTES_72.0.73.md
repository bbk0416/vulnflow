# VulnFlow 72.0.73 — Scanner import integrity patch

72.0.73 is a narrow defect release on the feature-frozen 72.0.72 Free Public Beta line.

## Fixed

- CSV rows with non-empty cells beyond the declared header width are rejected instead of silently truncating data.
- Malformed CSV quoting, including unterminated quoted fields that could absorb later physical rows, is rejected as a format error.
- XLSX parsing now defines header width by the last non-empty header cell and rejects later non-empty cells beyond that range instead of silently ignoring them.
- Trailing empty CSV cells remain accepted, and short rows continue to be padded as before.

## Compatibility

- SQLite schema: 46 (unchanged).
- Runtime dependency lock: unchanged.
- Finding canonical model, reconciliation semantics, remediation verification, API contracts, and supported Python 3.12/3.13 range: unchanged.

## Release rationale

This is the first post-freeze core patch because the defect can make an import appear successful while discarding source data. That meets the project policy for a reproducible scanner/data-integrity fix and therefore warrants a new core version rather than silently replacing the 72.0.72 runtime under its frozen tag.
