# VulnFlow 72.0.63 — Detached isolated-route transfer

VulnFlow 72.0.63 keeps SQLite schema 46 and adds no product feature. It fixes the FastAPI 0.140.9 compatibility failure exposed by the independent Windows 72.0.62 run.

## Evidence

The Windows run verified the 72.0.62 source and manifest, then collected 144 group-3 tests. Nine tests failed because every isolated application had zero `APIRoute` entries and `/health/live` and `/health/ready` returned 404. FastAPI 0.140.9 retains the original `APIRouter` through an included-router wrapper instead of eagerly copying its routes, so clearing the source list also removed the application's effective routes.

## Change

- Isolated router assembly no longer calls `FastAPI.include_router()`.
- Each private source `APIRoute` is rebound to the owning application as its dependency-overrides provider and its request handler is refreshed.
- The route objects are transferred directly to `app.router.routes`, the router-change marker is invoked when available, and only then is the private source list cleared.
- Process-level compatibility routers continue to use the normal FastAPI include path.
- The application still owns 276 direct `APIRoute` objects, supports repeated lifespans, and leaves no route or namespace growth after collection.

## Regression contract

Four v122 tests require isolated assembly to succeed even when `FastAPI.include_router()` is rejected, verify direct application ownership and dependency-provider binding, confirm restart behavior, and reject repeated route or namespace growth. The public core suite contains 643 tests plus three separate Chromium E2E tests.
