# VulnFlow Free — Public Beta 72.0.84

72.0.84 is a **Tenable/Nessus patch-availability correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import defect without changing SQLite schema 46 or dependency package pins.

## Fixed

- Honor Tenable `.nessus` `ReportItem/has_patch` as the authoritative structured patch-availability signal when the field is present.
- Prevent non-empty generic `solution` guidance from overriding an explicit `has_patch=false`.
- Preserve explicit `has_patch=true` even when solution text is absent.
- Treat malformed non-boolean `has_patch` values as patch unavailable and emit a parser warning instead of guessing from remediation text.
- Preserve the historical solution-text fallback only for older `.nessus` exports that omit `has_patch` entirely.

## Regression coverage

Three new import regressions cover explicit false, explicit true, malformed fail-closed handling, and the legacy no-`has_patch` fallback. The public suite is now 709 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 123).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Supported scanner connector set: unchanged
- Product feature scope: unchanged
- Official 72.0.83 tag and release assets remain immutable historical release artifacts.
