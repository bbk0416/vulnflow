# VulnFlow 72.0.62 — Isolated source-route release

VulnFlow 72.0.62 keeps SQLite schema 46 and adds no product feature. It closes the remaining Windows CPython 3.13 retention path by releasing the source `APIRouter.routes` collection after FastAPI has copied those routes into an isolated application.

## Evidence

The independent Windows 72.0.61 attribution was reproduced twice. Eight completed application lifecycles retained no FastAPI applications, but retained exactly 2,208 `APIRoute` objects (`276 × 8`), 128 private router namespaces, 128 globals dictionaries, and 2,584 runtime functions. Pydantic validators and FastAPI dependency metadata remained reachable through the source-router cycle, producing about 32.6 MiB growth over six measured samples and 53.3 MiB in the full twelve-cycle soak.

## Change

- `include_router()` still copies all 276 route definitions into each isolated application.
- Immediately after that copy, only the private source `APIRouter.routes` list is cleared.
- The application-owned routes, endpoint globals, per-application dependency isolation, browser workflows, and same-application restart remain intact.
- Process-level compatibility routers are not cleared.
- The 24 MiB Python-allocation limit remains unchanged.

## Regression contract

Four v121 tests cover source-route release, route-count preservation, restart behavior, repeated garbage collection without route or namespace growth, and primary-router preservation. The public core suite contains 639 tests plus three separate Chromium E2E tests.
