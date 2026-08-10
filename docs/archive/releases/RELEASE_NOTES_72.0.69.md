# VulnFlow 72.0.69 — FastAPI public router registration compatibility


> **Erratum (72.0.70):** Windows FastAPI 0.140.9 did not drop the four pilot routes.
> It represents included routers as a lazy route-context branch, so direct
> `APIRoute` inspection reports 272 while the effective inventory remains 276.
> The v59 public API change is retained, but the original regression diagnosis
> and direct-route-count validation were incorrect.

VulnFlow 72.0.69 fixes the Windows FastAPI 0.140.9 regression discovered during independent v58 validation. The four request-scoped pilot routes were present on the shared `APIRouter` but were absent from secondary application route tables because the migration used the lower-level `app.router.include_router()` implementation path.

## Changes

- Registers request-scoped DI routers through the supported `app.include_router()` API.
- Keeps direct `APIRoute` transfer only for the remaining 15 legacy cloned router modules.
- Narrows the former “no FastAPI include” regression so it rejects inclusion of legacy cloned routers while requiring normal inclusion of the shared DI router.
- Adds a dedicated contract that observes the public FastAPI include call and verifies shared endpoint identity.
- Restores all 276 routes while retaining request-scoped application isolation and SQLite schema 46.

## Root cause

The v58 local environment used FastAPI 0.128.2, where the lower-level router call happened to populate the application route table. The locked Windows environment used FastAPI 0.140.9, where that implementation shortcut did not activate the four shared routes. The supported public application API is now the only registration path for migrated DI routers.

## Limitations

Fifteen router modules remain on the in-memory cloning and direct-transfer compatibility path. This hotfix does not expand the DI migration scope.
