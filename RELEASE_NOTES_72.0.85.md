# VulnFlow Free — Public Beta 72.0.85

72.0.85 is a **Greenbone/OpenVAS delta-result import correctness patch** on the feature-frozen 72.0.72 line. It fixes an independently reproduced scanner-import data-integrity defect without changing SQLite schema 46 or dependency package pins.

## Fixed

- Treat only the outer/current Greenbone XML `<result>` elements as importable findings.
- Do not import a previous comparison `<result>` embedded under `<delta>` as a separate active finding.
- Preserve ordinary XML report imports and direct result-document compatibility by stopping recursive traversal once the first importable result boundary is reached.

## Regression coverage

One new regression covers a current result containing a historical nested delta result and proves only the current CVE is imported. The public suite is now 710 tests across seven non-overlapping bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 124).

## Unchanged boundaries

- SQLite schema: 46
- Runtime/development dependency package pins: unchanged
- Supported scanner connector set: unchanged
- Product feature scope: unchanged
- Official 72.0.84 tag and release assets remain immutable historical release artifacts.
