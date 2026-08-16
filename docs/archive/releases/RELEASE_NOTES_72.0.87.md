# VulnFlow Free — Public Beta 72.0.87

72.0.87 is a **Tenable/Nessus SMBIOS asset-identity false-merge correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

- Do not promote SMBIOS all-zero or all-FF `bios-uuid` values from `.nessus` HostProperties into authoritative canonical `asset_id`.
- Preserve the existing `host-uuid` priority and valid BIOS UUID behavior.
- When an absent-UUID sentinel is present, continue to the existing `mcafee-epo-guid` fallback instead of collapsing unrelated hosts onto the sentinel.
- Prevent distinct hosts with different IP/FQDN values from false-merging solely because both report the same SMBIOS “UUID not present” marker.

## Regression coverage

One new end-to-end regression covers all-zero and all-FF BIOS UUID sentinels, valid BIOS UUID preservation, McAfee ePO fallback, and ingestion of two distinct hosts that previously collapsed into one asset. The public suite is now 712 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 126).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Supported scanner connector set: unchanged
- Product feature scope: unchanged
- Official 72.0.86 tag and release assets remain immutable historical release artifacts.
