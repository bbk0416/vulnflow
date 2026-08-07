# FastAPI callable-cache lifecycle release

## Failure mode

VulnFlow creates private router functions for isolated application instances so route globals cannot be overwritten by another `create_app()` call. FastAPI releases that cache callable classification may retain those dynamically created functions after the owning application and routes are gone.

The Windows diagnostic showed linear growth: each three-application batch retained 828 endpoint functions and 48 private router namespaces. Direct referrers were globals dictionaries and FastAPI `_CallIdentity` objects.

## Cleanup boundary

At isolated lifespan shutdown VulnFlow:

1. removes the application back-reference from private router globals;
2. clears available FastAPI callable-classification LRU wrappers;
3. releases the application context reference.

The cleanup is feature-detected because the private cache location varies by FastAPI release. Missing caches are a supported no-op. The primary process application is never cleaned through this path.

## Safety properties

Clearing classification caches does not change route definitions or dependency graphs. FastAPI recomputes whether a callable is a coroutine, generator, or async generator on the next use. This trades a bounded reclassification cost for deterministic release of isolated endpoint functions.
