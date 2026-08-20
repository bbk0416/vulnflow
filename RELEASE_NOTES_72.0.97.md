# VulnFlow 72.0.97 — Greenbone XML result path identity

72.0.97 is a **Greenbone GMP XML result-path finding-identity correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import finding-loss defect without changing SQLite schema 46 or dependency package pins.

## Defect

Greenbone GMP result XML can carry a result-level `path` describing the local path on the scanned host, for example the affected file location. VulnFlow 72.0.96 parsed the result host, port, NVT, CVE and risk/remediation fields but discarded `<path>`. Two legitimate results with the same asset, CVE, NVT and host-level port but different local paths therefore produced the same canonical component and the same generated finding identity. A batch containing both scanner results could reject the second as a duplicate instead of preserving both findings.

## Fix

72.0.97 preserves a non-empty Greenbone XML result `<path>` in the canonical component identity and operator notes. Existing non-zero numeric `port/protocol` endpoint identity remains intact, and XML results without a path retain their historical component identity. Greenbone CSV, Nessus, generic imports, per-CVE XML EPSS attribution and multi-CVE CSV EPSS fail-safe behavior are unchanged.

## Regression contract

One end-to-end regression verifies two Greenbone XML results with the same asset/CVE/NVT and different local paths, including scanner detection, canonical mapping, generated finding identity, batch import, and two persisted findings. The public collection contract is 722 tests (78 + 76 + 168 + 80 + 117 + 67 + 136); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
