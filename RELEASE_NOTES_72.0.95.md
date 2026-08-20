# VulnFlow 72.0.95 — Greenbone XML per-CVE EPSS attribution

72.0.95 is a **Greenbone GMP XML per-CVE EPSS attribution correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import risk-data misattribution defect without changing SQLite schema 46 or dependency package pins.

## Defect

Greenbone GMP defines `nvt/epss/max_severity` as EPSS information for the referenced CVE with the highest severity and identifies that representative CVE in the nested `cve@id`. It separately defines `nvt/epss/max_epss` as EPSS information for the referenced CVE with the highest EPSS score. VulnFlow 72.0.94 read only the `max_severity` score/percentile and copied those values onto every canonical CVE row expanded from the NVT. A multi-CVE NVT could therefore assign one CVE's EPSS probability and percentile to a different CVE, distorting prioritization.

## Fix

72.0.95 binds each Greenbone XML EPSS tuple to the nested representative `cve@id` before canonical CVE expansion. `max_severity` values are assigned only to their representative CVE; `max_epss` values are preserved for their own representative CVE when different. Other referenced CVEs remain without scanner-supplied EPSS rather than receiving another CVE's value. Single-CVE exports with a missing representative ID retain a safe compatibility fallback.

Existing XML endpoint identity, solution semantics, CSV EPSS behavior, Customizable CSV, Nessus and generic import behavior remain unchanged.

## Regression contract

One end-to-end regression verifies a two-CVE Greenbone XML NVT where `max_severity` and `max_epss` identify different CVEs, including canonical mapping, normalization, batch import, and persisted per-CVE EPSS values. The public collection contract is 720 tests (78 + 76 + 168 + 80 + 117 + 67 + 134); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
