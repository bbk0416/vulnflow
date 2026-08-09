# VulnFlow 72.0.65 — FastAPI callable-cache lifecycle release

VulnFlow 72.0.65 fixes the remaining isolated-router lifetime leak observed on Windows CPython 3.13 with FastAPI 0.140.9. The application and `APIRoute` objects were released, but FastAPI callable-classification LRU caches retained private endpoint functions through `_CallIdentity` keys. Each retained endpoint kept its router globals and runtime namespace reachable.

## Product correction

- Clear the available FastAPI generator, async-generator, and coroutine callable-classification caches when an isolated application lifespan ends.
- Discover both historical private cache locations and treat versions without those caches as a supported no-op.
- Deduplicate aliases before clearing, so a re-exported wrapper is cleared once.
- Keep the primary process application outside this cleanup boundary.

## Evidence contract

- Add four v123 regressions for cache discovery, absent-private-API compatibility, isolated-lifespan cleanup, and primary-runtime preservation.
- Expand the public core contract from 643 to 647 tests; group 3 expands from 148 to 152.
- Keep SQLite schema 46, the 24 MiB Python-allocation bound, and all router ownership contracts unchanged.
