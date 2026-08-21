# VulnFlow Free — Public Beta 72.0.98

72.0.98 is a focused Greenbone multi-CVE CVSS attribution correctness patch on the feature-frozen 72.0.72 line. It fixes a reproduced scanner-import risk-score attribution defect without changing SQLite schema 46 or dependency package pins.

## Defect

Greenbone NVTs can reference multiple CVEs while exposing a single NVT-level `cvss_base` / result severity derived from the highest-severity referenced CVE. VulnFlow 72.0.97 expanded every referenced CVE into its own canonical finding row but copied that one CVSS value onto every row. A lower-severity CVE could therefore inherit another CVE's higher scanner-supplied CVSS, changing persisted risk inputs and prioritization.

The same ambiguity exists in current detailed Greenbone CSV exports: a row may contain multiple `CVE references` but does not identify which CVE owns the row-level Severity value.

## Fix

For GMP XML, 72.0.98 reuses the representative CVE metadata already present under `nvt/epss/max_severity` and `nvt/epss/max_epss`: nested `cve@id` selects the represented CVE and nested `<severity>` supplies that CVE's CVSS. Scanner-supplied CVSS is no longer copied to unrelated referenced CVEs. Single-CVE XML retains the historical NVT/result severity fallback.

For detailed Greenbone CSV, single-CVE Severity is preserved. When a row expands to multiple CVEs and no representative CVE ID is available, per-CVE CVSS is left empty and a parser warning is emitted rather than guessing.

The 72.0.97 XML result-path identity fix, 72.0.96 CSV multi-CVE EPSS fail-safe, 72.0.95 XML per-CVE EPSS attribution, Nessus behavior, generic import behavior, schema 46, and dependency package pins are unchanged.

## Regression contract

One end-to-end regression verifies XML representative-CVE CVSS attribution through canonical mapping, normalization, batch import, and persisted findings, and verifies detailed CSV multi-CVE CVSS fail-safe warning behavior. The public collection contract is 723 tests (78 + 76 + 168 + 80 + 117 + 67 + 137); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
