# VulnFlow Free — Public Beta 72.0.86

72.0.86 is a **Greenbone/OpenVAS asset-identity continuity correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

- Preserve the Greenbone result host `<asset asset_id="...">` UUID as canonical `asset_id` during XML imports.
- Keep the scanner-provided stable asset identity when IP addresses or hostnames change between scans, preventing one Greenbone asset from being split into duplicate VulnFlow assets/findings solely because network naming changed.
- Continue using existing IP/FQDN/hostname identity signals when Greenbone omits the asset UUID.

## Regression coverage

One new regression parses two Greenbone XML results for the same `asset_id` across changed IP/FQDN values and proves the second import resolves to the existing asset/finding. The public suite is now 711 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 125).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Supported scanner connector set: unchanged
- Product feature scope: unchanged
- Official 72.0.85 tag and release assets remain immutable historical release artifacts.
