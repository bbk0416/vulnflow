# VulnFlow 72.0.94 — Greenbone XML EPSS preservation

72.0.94 is a **current Greenbone GMP XML risk-intelligence preservation correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import data-loss defect without changing SQLite schema 46 or dependency package pins.

## Defect

Current Greenbone GMP result NVTs may include `epss/max_severity/score` and `epss/max_severity/percentile`, representing EPSS information for the referenced CVE with the highest severity. VulnFlow 72.0.93 preserved the current detailed CSV EPSS fields but the OpenVAS XML adapter ignored the GMP XML EPSS structure. A valid result containing `score=0.82` and `percentile=0.99` therefore lost both canonical EPSS inputs during XML import.

## Fix

72.0.94 preserves `nvt/epss/max_severity/score` as canonical `epss` and `nvt/epss/max_severity/percentile` as canonical `epss_percentile`. It intentionally follows Greenbone's `max_severity` EPSS contract rather than substituting `max_epss`. Existing XML CVE references, endpoint identity, solution semantics, CSV EPSS behavior, Customizable CSV, Nessus and generic import behavior remain backward compatible.

## Regression contract

One end-to-end regression verifies Greenbone XML parsing, `max_severity` EPSS score/percentile extraction, canonical mapping, normalization, batch import, and persisted values. The public collection contract is 719 tests (78 + 76 + 168 + 80 + 117 + 67 + 133); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
