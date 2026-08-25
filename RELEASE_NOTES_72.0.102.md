# VulnFlow Free — Public Beta 72.0.102

72.0.102 is a focused Nessus single-label host-fqdn import correctness patch on the feature-frozen 72.0.72 line. It fixes a defect reproduced from a real public NessusClientData_v2 export without changing SQLite schema 46 or dependency package pins.

## Correctness fix

A real Nessus export can contain a valid host IP together with a single-label value such as `kali` in the `host-fqdn` HostProperties tag. VulnFlow 72.0.101 copied that scanner value directly into the canonical FQDN field. Canonical FQDN validation correctly rejects names without a dot, so an otherwise valid CVE finding could be rejected during preview even though the host had a valid IP address and hostname.

72.0.102 treats Nessus `host-fqdn` as canonical FQDN only when it passes the same scanner-adapter FQDN prefilter already used by Greenbone. A single-label value remains available as the asset/hostname label while the canonical FQDN field is left blank, allowing the valid IP-backed finding to normalize and import. Valid fully-qualified Nessus host names are unchanged.

## Validation contract

One regression reproduces the real scanner shape with `host-fqdn=kali` and `host-ip=192.168.1.5`, verifies that the short label is retained as the asset name, is not promoted to canonical FQDN, and that the CVE finding normalizes and persists successfully. Existing Nessus multi-port and multi-CVE CVSS behavior, Greenbone affected-software/OCI/path identity, and generic import behavior remain unchanged. The public collection contract is 727 tests (78 + 76 + 168 + 80 + 117 + 67 + 141); platform-specific skips remain explicit.

SQLite schema remains 46 and dependency package pins are unchanged.
