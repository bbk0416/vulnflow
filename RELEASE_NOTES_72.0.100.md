# VulnFlow Free — Public Beta 72.0.100

72.0.100 is a focused Greenbone GMP OCI-image result identity correctness patch on the feature-frozen 72.0.72 line. It fixes a reproduced scanner-import finding-identity defect without changing SQLite schema 46 or dependency package pins.

## Defect

Greenbone GMP 22.8 results can include an `oci_image` object with the image name, digest, registry, repository path, and short name. VulnFlow 72.0.99 preserved host, NVT/CVE, port, and local result path in canonical finding identity, but ignored `oci_image`. Two valid results for different OCI image digests could therefore normalize to the same scanner finding ID and canonical component when the host, NVT, CVE, port, and local path matched, causing a duplicate finding-id rejection instead of preserving both image findings.

## Fix

For Greenbone XML results, 72.0.100 adds the OCI image digest to component identity when available and uses the full image name only as a fallback. OCI image name and digest are also retained in operator notes. Existing Greenbone port/path identity, multi-CVE CVSS/EPSS attribution, Nessus behavior, and generic import behavior are unchanged.

The 72.0.99 Nessus multi-CVE CVSS fail-safe, 72.0.98 Greenbone multi-CVE CVSS attribution, 72.0.97 XML result-path identity, 72.0.96 CSV multi-CVE EPSS fail-safe, 72.0.95 XML per-CVE EPSS attribution, schema 46, and dependency package pins remain unchanged.

## Regression contract

One end-to-end regression verifies that two Greenbone GMP results with the same host, NVT, CVE, port, and local path but different OCI image digests produce distinct component identities, distinct automatic finding IDs, and two persisted findings. Existing Greenbone result-path and multi-CVE CVSS regressions remain green. The public collection contract is 725 tests (78 + 76 + 168 + 80 + 117 + 67 + 139); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
