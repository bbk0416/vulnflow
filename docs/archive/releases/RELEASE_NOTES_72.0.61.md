# VulnFlow 72.0.61 — Router namespace runtime release

VulnFlow 72.0.61 keeps SQLite schema 46 and adds no product feature. It closes the Windows-only retention left after 72.0.60 by executing each isolated router source in a private plain namespace rather than a synthetic `ModuleType` object.

## Evidence

The independent Windows 72.0.60 focused run released every FastAPI application weak reference but still retained 48 synthetic router modules after three lifecycles (`64 -> 112`). Earlier attribution showed 16 router modules per application and approximately 11.16 MiB of allocation growth per lifecycle.

## Change

- Isolated router source still receives a distinct globals dictionary for each application.
- The holder is a `SimpleNamespace`, not a module object, and is never registered in `sys.modules`.
- Existing route functions, dependency installation, application restart, and primary compatibility routers are preserved.
- Lifespan shutdown still removes the owning `app` back-reference.
- The bounded public runner removes inherited `FORCE_COLOR` before JSON-emitting CLI regressions.

## Regression contract

Four v120 tests cover namespace type, absence from `sys.modules`, restart-safe app rebinding, and repeated garbage collection without synthetic module growth. The public core suite contains 635 tests plus three separate Chromium E2E tests.
