# VulnFlow Free — Public Beta 72.0.83

72.0.83 is a **Greenbone/OpenVAS remediation-semantics correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import defect without changing SQLite schema 46 or dependency package pins.

## Fixed

- Interpret Greenbone `Solution Type` as structured remediation metadata instead of treating any non-empty solution text as proof that a patch exists.
- Mark `patch_available=1` only for explicit `VendorFix` solution types (including spacing/hyphen normalization).
- Map explicit `Workaround`, `Mitigation`, `NoneAvailable`, `WillNotFix`, and other non-`VendorFix` solution types to `patch_available=0`.
- Preserve the historical solution-text fallback only for older OpenVAS/Greenbone exports that omit `Solution Type` entirely.
- Prevent workaround/mitigation rows from incorrectly receiving the patch-available prioritization weight or suppressing mitigation-required handling.

## Regression coverage

Two new import regressions cover Greenbone XML and CSV solution-type semantics, including the legacy no-type fallback. The public suite is now 706 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 120).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Supported scanner connector set: unchanged
- Product feature scope: unchanged
- Official 72.0.82 tag and release assets remain immutable historical release artifacts.
