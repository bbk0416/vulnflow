# VulnFlow 72.0.77

72.0.77 is a narrow scanner-source and internationalized asset-identity integrity patch on the feature-frozen 72.0.72 line.

## Fixed

- Apply the scanner-source case-fold contract with Python Unicode `casefold()` during snapshot absence reconciliation, so non-ASCII case-only source labels cannot leave missing observations incorrectly PRESENT.
- Collapse case-fold-equivalent scanner-source labels to one logical source in canonical `scanner_source` / `source_count` aggregation, including incremental imports that retain multiple native source records.
- Treat stable IDNA Unicode U-label and punycode A-label spellings of the same FQDN as equivalent during asset resolution and identifier collision checks, preventing representation-only asset splits while preserving authoritative scanner asset-ID separation.

## Compatibility boundary

- Existing stored FQDN spellings are not rewritten; equivalence matching is applied at resolution time, avoiding a schema/data rewrite for existing databases.
- IDNA aliasing is only enabled when the built-in codec round-trips the ASCII form exactly; non-reversible mappings are not silently conflated.
- Enterprise underscore FQDN compatibility, CSV/XLSX parsing, scanner connectors, and all prior preview/apply protections are unchanged.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
