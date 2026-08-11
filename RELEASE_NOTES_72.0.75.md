# VulnFlow 72.0.75

72.0.75 is a narrow scanner-import preview/reconciliation and source-provenance patch on the feature-frozen 72.0.72 line.

## Fixed

- Validate explicit `fqdn`, `ip_address`, and `mac_address` values during finding-import preview with the same asset-identity rules used during reconciliation, so invalid rows are surfaced before apply.
- Accept a single matching bracket pair around valid IPv6 literals in the central IP identifier normalizer.
- Classify `asset_name` IP literals through that same central normalizer so bracketed IPv6 targets do not create a false `HOSTNAME` alias in addition to the canonical `IP_ADDRESS`.
- Track the physical starting line of each CSV record, including records with embedded quoted newlines, so preview and exported row errors point to the real source row.
- Track the actual XLSX worksheet row number when leading blank rows precede the header, including overflow error locations.

## Compatibility boundary

- Generic CSV encoding support remains UTF-8 variants plus CP949/EUC-KR fallback. UTF-16 is not newly claimed or accepted by this patch.
- Leading textual description/preamble rows are not newly treated as CSV/XLSX headers; the existing header contract remains unchanged.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- Scanner import overflow/malformed-CSV protections from 72.0.73 remain in force.
- Scanner hostname/IP exact classification from 72.0.74 remains in force.
- The feature-frozen remediation closeout product scope is unchanged.
