# VulnFlow 72.0.93 — Greenbone EPSS preservation

72.0.93 is a **current Greenbone detailed CSV risk-intelligence preservation correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import data-loss defect without changing SQLite schema 46 or dependency package pins.

## Defect

Current Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT detailed CSV exports include `EPSS score` and `EPSS percentile`. VulnFlow 72.0.92 correctly recognized the current Greenbone detailed CSV profile and preserved CVE/endpoint identity, but the OpenVAS CSV adapter did not copy either EPSS field into canonical import rows. A source row containing `EPSS score=0.82` and `EPSS percentile=0.99` therefore reached normalization with empty EPSS values and was persisted as zero, silently changing prioritization input.

## Fix

72.0.93 preserves `EPSS score` as canonical `epss` and `EPSS percentile` as canonical `epss_percentile`. The existing canonical import mapping contract now exposes `epss_percentile`, which already exists in schema 46. Existing Greenbone `CVE references`, endpoint identity, Customizable CSV, XML, Nessus and generic import behavior remain backward compatible.

## Regression contract

One end-to-end regression verifies current detailed CSV auto-detection, EPSS score/percentile extraction, canonical mapping, normalization, batch import, and persisted values. The public collection contract is 718 tests (78 + 76 + 168 + 80 + 117 + 67 + 132); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
