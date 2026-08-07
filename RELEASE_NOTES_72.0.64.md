# VulnFlow 72.0.64 — Windows GC-baseline contract correction

VulnFlow 72.0.64 keeps the 72.0.63 product implementation and SQLite schema 46 unchanged. It corrects one Windows-only false negative in the public regression contract.

## Independent Windows evidence

The 72.0.63 focused run verified the source and 629-file public manifest. All seven external checks produced five passes, one unavailable Docker engine, and one not-provided customer scanner corpus. The only failing gate was one group-3 assertion whose process-wide `APIRoute` count decreased from 1,380 to 828 after delayed collection of objects created by earlier tests. The application health route remained available and the three applications created by the failing test were collected.

## Contract correction

- Repeated isolated-application tests retain weak references to every created application, all 276 transferred routes per application, and their endpoint functions.
- After each lifecycle and final garbage collection, every one of those weak references must be dead.
- Process-wide route and runtime-namespace counts may decrease when earlier tests are finally collected, but may not increase above the pre-test baseline.
- No production module, dependency, schema, threshold, or platform skip changes.

## Regression scope

The public core suite remains 643 tests in seven bounded groups. The corrected assertions are in the existing v121 and v122 test modules.
