# Windows isolated source-route release

VulnFlow 72.0.62 removes the remaining framework-metadata retention observed on CPython 3.13 for Windows.

## Observed boundary

After 72.0.61, the FastAPI application object itself was reclaimed and synthetic modules were gone, but every completed isolated lifecycle retained one complete source router set: 276 `APIRoute` objects, 16 private namespaces, their globals dictionaries and endpoint functions, plus the related FastAPI and Pydantic dependency/schema graph. Eight lifecycles therefore retained 2,208 routes.

The exact multiple demonstrates that the retained objects were the private source `APIRouter.routes`, not the application-owned copies. `FastAPI.include_router()` already creates the application routes, so the private source list is no longer needed after assembly.

## Runtime contract

For isolated applications only, router assembly now performs these steps:

1. compile each router source into a private globals namespace;
2. install the application-specific dependencies;
3. copy each source router into the application with `include_router()`;
4. clear the private source router's `routes` list.

The application route table remains complete. A later lifespan on the same application reuses those application-owned routes and rebinds mutable dependencies and the owning application reference. Process-level compatibility routers remain untouched.

## Acceptance

- isolated source routers retain zero route objects after assembly;
- each application still owns 276 `APIRoute` objects;
- health and ready endpoints pass across repeated lifespans;
- completed isolated applications add no surviving route or runtime-namespace growth;
- primary compatibility routers retain their route definitions;
- the 24 MiB Python allocation bound remains unchanged.
