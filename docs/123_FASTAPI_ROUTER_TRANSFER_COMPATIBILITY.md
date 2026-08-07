# FastAPI router-transfer compatibility

VulnFlow 72.0.63 separates isolated application assembly from FastAPI's changing `include_router()` ownership semantics.

## Observed boundary

FastAPI 0.140.9 represents an included router with a wrapper that retains the original `APIRouter`. The 72.0.62 implementation assumed the earlier eager-copy behavior and cleared the private source route list immediately after inclusion. Under the pinned Windows environment this left the application with zero effective API routes and produced 404 responses for health endpoints.

## Runtime contract

For isolated applications only, router assembly now performs these steps:

1. compile each router source into a private globals namespace;
2. install application-specific dependencies;
3. rebind every source `APIRoute` to the owning application's dependency-overrides provider and refresh its request handler;
4. transfer those route objects directly to `app.router.routes`;
5. notify FastAPI's route-version tracker when that hook is available;
6. clear the now-empty private source router list.

The process-level compatibility application still uses the framework's standard include path. The isolated path therefore does not depend on whether a FastAPI version copies or retains child routers.

## Acceptance

- isolated assembly never calls `FastAPI.include_router()`;
- each isolated application owns 276 direct `APIRoute` objects;
- private source routers retain zero route objects after assembly;
- health and ready endpoints pass across repeated lifespans;
- completed isolated applications add no surviving route or namespace growth;
- the 24 MiB Python-allocation bound remains unchanged.
