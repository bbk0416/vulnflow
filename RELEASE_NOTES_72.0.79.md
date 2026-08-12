# VulnFlow 72.0.79

72.0.79 is a narrow scanner source/canonical identity parity patch on the feature-frozen 72.0.72 line.

## Fixed

- Normalize the textual component/product portion of scanner-independent canonical finding identity to Unicode NFC before case folding. Canonically equivalent composed/decomposed spellings such as `café-lib` and `cafe\u0301-lib` now resolve to one canonical finding instead of splitting into duplicates.
- Normalize all identity fields used for generated `AUTO-*` finding IDs to Unicode NFC before case folding. The same scanner/source row now keeps a stable generated finding ID when Unicode text or the scanner-source label changes only between NFC and NFD representations.
- Align preview duplicate `finding_id` detection with the persisted source-record identity contract. Case-fold- or NFC-equivalent source-native IDs are rejected during preview and again fail-closed at apply, rather than being shown as valid rows and rejected only during persistence.
- Preserve the existing ASCII AUTO finding-ID hash contract for unchanged ASCII inputs.

## Compatibility boundary

- Existing valid ASCII-generated AUTO finding IDs are unchanged.
- Pre-72.0.79 databases that already contain duplicate source records created only by Unicode normalization differences are not automatically rewritten; the patch prevents new splits and keeps canonical reconciliation behavior fail-closed.
- The patch does not change scanner-native IDs supplied explicitly by scanners; it only aligns duplicate detection with the source-record identity semantics already used by persistence.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- Scanner connectors and supported scanner file formats are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
