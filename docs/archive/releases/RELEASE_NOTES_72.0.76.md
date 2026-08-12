# VulnFlow 72.0.76

72.0.76 is a narrow scanner-import data-integrity and asset-identity reconciliation patch on the feature-frozen 72.0.72 line.

## Fixed

- Preserve every supported CSV/XLSX column when duplicate-header suffixes collide with an already-present header name, preventing silent cell overwrite during row-dictionary construction.
- Reject malformed explicit FQDN asset identifiers such as whitespace/slash-containing names, invalid hyphen placement, overlong labels, and literal IP addresses instead of accepting them as FQDNs.
- Reconcile scanner sources consistently across case-only source-name changes by resolving source records through the case-folded `source_record_id`, preventing re-import crashes on the existing primary-key contract.
- Treat case-only scanner-source variants as the same source during snapshot absence reconciliation.

## Compatibility boundary

- Valid FQDN normalization remains case-insensitive and continues to accept the existing enterprise underscore compatibility form.
- Generic CSV/XLSX parsing, UTF-8/CP949/EUC-KR encoding support, scanner connectors, and product feature scope are unchanged.
- The 72.0.75 preview/apply identity checks, bracketed IPv6 handling, and physical source-row provenance protections remain in force.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
