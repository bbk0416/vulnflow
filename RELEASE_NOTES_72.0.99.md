# VulnFlow Free — Public Beta 72.0.99

72.0.99 is a focused Nessus multi-CVE CVSS attribution correctness patch on the feature-frozen 72.0.72 line. It fixes a reproduced scanner-import risk-score attribution defect without changing SQLite schema 46 or dependency package pins.

## Defect

Tenable plugins can reference multiple CVEs while exposing one plugin-level CVSS score in a Nessus `ReportItem`. VulnFlow 72.0.98 expanded every referenced CVE into its own canonical finding row but copied that one plugin-level CVSS value onto every row. Because the `.nessus` export does not identify a per-CVE owner for that score, unrelated CVEs could inherit a score that belongs to the plugin as a whole rather than to that individual CVE, changing persisted risk inputs and prioritization.

## Fix

For single-CVE Nessus results, 72.0.99 preserves the existing CVSS4, CVSS3, then CVSS2 fallback. For multi-CVE Nessus `ReportItem` values, per-CVE CVSS is left empty and a parser warning is emitted rather than guessing which CVE owns the plugin-level score.

The 72.0.98 Greenbone multi-CVE CVSS attribution fix, 72.0.97 XML result-path identity fix, 72.0.96 CSV multi-CVE EPSS fail-safe, 72.0.95 XML per-CVE EPSS attribution, generic import behavior, schema 46, and dependency package pins are unchanged.

## Regression contract

One end-to-end regression verifies that a multi-CVE Nessus `ReportItem` expands to all referenced CVEs without copying the plugin-level CVSS, emits the fail-safe warning, normalizes without fabricated per-CVE scores, and persists all findings. Existing single-CVE Nessus CVSS4 and Greenbone multi-CVE CVSS regressions remain green. The public collection contract is 724 tests (78 + 76 + 168 + 80 + 117 + 67 + 138); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
