# VulnFlow 72.0.96 — Greenbone CSV multi-CVE EPSS attribution fail-safe

72.0.96 is a **Greenbone detailed-CSV multi-CVE EPSS attribution correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import risk-data misattribution defect without changing SQLite schema 46 or dependency package pins.

## Defect

Greenbone GMP defines the NVT `epss_score`/`epss_percentile` values as the EPSS metrics of the referenced CVE with the highest severity. Current detailed CSV exports expose `EPSS score`, `EPSS percentile`, and `CVE references`, but do not identify which referenced CVE owns that representative EPSS tuple. VulnFlow 72.0.95 expanded a multi-CVE CSV row into one canonical row per CVE and copied the same NVT-level EPSS tuple onto every expanded CVE. A multi-CVE vulnerability test could therefore assign one CVE's exploitation probability and percentile to unrelated CVEs.

## Fix

72.0.96 preserves `EPSS score`/`EPSS percentile` for single-CVE Greenbone CSV rows. When a CSV row references multiple CVEs, VulnFlow no longer guesses the representative CVE: it leaves per-CVE `epss`/`epss_percentile` empty and emits a parser warning. This retains the CVE findings while preventing false risk-data attribution.

72.0.95 Greenbone GMP XML per-CVE attribution remains unchanged because XML provides nested `cve@id` identifiers for `max_severity` and `max_epss`. Existing endpoint identity, solution semantics, Customizable CSV, legacy CSV, Nessus and generic import behavior remain unchanged.

## Regression contract

One end-to-end regression verifies a two-CVE current Greenbone detailed CSV row with EPSS fields, including scanner detection, canonical CVE expansion, fail-safe EPSS clearing, parser warning, normalization, batch import, and persisted values. The public collection contract is 721 tests (78 + 76 + 168 + 80 + 117 + 67 + 135); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
