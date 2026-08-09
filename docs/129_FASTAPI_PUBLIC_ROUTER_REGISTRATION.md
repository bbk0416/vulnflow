# FastAPI public router registration boundary

## 72.0.70 correction

Request-scoped router modules are ordinary shared `APIRouter` instances. They must be registered through `FastAPI.include_router()` rather than by calling the application router implementation directly.

The Windows 72.0.68 validation used FastAPI 0.140.9 and produced 272 routes instead of 276. All four missing routes belonged to `app.routers.pilot`. The shared router still contained its four route definitions, proving that dependency conversion was intact and registration alone failed.

## Contract

- Modules in `CONTEXT_ROUTER_MODULES` use `app.include_router(module.router)`.
- Legacy cloned modules never use `FastAPI.include_router()` and continue through direct application-owned `APIRoute` transfer.
- Every application contains 276 `APIRoute` entries.
- Shared DI endpoints preserve imported function identity across applications.
- Application context resolution remains request scoped through `request.app.state.vulnflow_context`.

This boundary avoids depending on framework implementation details while preserving the staged migration.

## 72.0.70 erratum

FastAPI 0.140.9 stores `include_router()` results as lazy route-context branches.
The four pilot routes were active even though direct `APIRoute` inspection saw
272 entries. The public `app.include_router()` path remains the supported API,
but route validation must use effective route contexts instead of assuming
that included routes are flattened into `app.router.routes`.
