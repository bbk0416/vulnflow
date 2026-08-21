# VulnFlow Free — Public Beta 72.0.101

72.0.101 is a focused Greenbone detailed-CSV affected-software identity correctness patch on the feature-frozen 72.0.72 line. It fixes a reproduced scanner-import finding-identity defect without changing SQLite schema 46 or dependency package pins.

## Correctness fix

Greenbone's official detailed CSV exports include `Affected software/operating system`. In 72.0.100 that field was discarded by the CSV adapter. Two rows for the same host, CVE, vulnerability name, and port but different affected software therefore generated the same automatic finding ID; a real batch then failed closed as duplicate finding IDs instead of preserving both observations.

72.0.101 retains the affected-software value in canonical component identity and operator notes. Rows that differ only by affected software remain distinct, while rows without that field keep the historical identity. Existing Greenbone XML path/OCI identity, multi-CVE CVSS/EPSS attribution, Nessus behavior, and generic import behavior are unchanged.

## Validation contract

One end-to-end regression verifies that two official-style Greenbone detailed-CSV rows with identical host/CVE/VT/port but different `Affected software/operating system` values produce distinct component identities, distinct automatic finding IDs, and two persisted findings. Existing Greenbone OCI-image/path and scanner import regressions remain green. The public collection contract is 726 tests (78 + 76 + 168 + 80 + 117 + 67 + 140); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
