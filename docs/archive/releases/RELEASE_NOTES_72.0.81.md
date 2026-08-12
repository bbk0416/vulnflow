# VulnFlow 72.0.81

72.0.81 is a narrow scanner-inventory identity and reconciliation-lifecycle integrity patch on the feature-frozen 72.0.72 line.

## Fixed

- Refresh canonical `product_version` and `component_version` when current PRESENT sources converge on one non-empty value, including the ordinary single-source reimport path. Conflicting multi-source values remain explicit rather than being overwritten arbitrarily.
- Apply an ACTIVE reconciliation decision only while its chosen PRESENT source currently supplies the selected field. If that source omits the field, the stored decision remains preserved but temporarily ineffective; it becomes effective again if the field later returns.
- Reuse an existing scanner-derived asset when asset inventory carries the same normalized external asset identity, instead of creating a competing inventory asset that can make the next scanner reimport fail authoritative-identity checks.
- Normalize inventory external IDs to Unicode NFC plus case folding across CSV duplicate detection, lookup, and linking, so canonically equivalent NFC/NFD spellings resolve to one asset.
- Reject duplicate normalized authoritative asset identifiers within one inventory apply batch before partial writes occur.

## Compatibility boundary

- Existing operator reconciliation decisions are retained; only their effective application now requires the chosen source to be PRESENT and currently supply the selected field.
- Existing valid scanner-derived assets can be enriched by matching inventory external IDs without changing the scanner source identity contract.
- Pre-72.0.81 databases that already contain split or competing asset records created by earlier inventory/scanner identity behavior are not automatically merged. The patch prevents new divergence and keeps ambiguous historical repair explicit.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- Scanner connectors and supported scanner file formats are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
