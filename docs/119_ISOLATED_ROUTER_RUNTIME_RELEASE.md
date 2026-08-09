# Isolated Router Runtime Release

## Problem

VulnFlow creates private router-module namespaces for additional FastAPI application instances so per-application settings and service hooks cannot overwrite each other. Each private module receives the owning FastAPI application through dependency injection. On Windows Python 3.13, completed lifespans retained that application reference and therefore the full route and Pydantic schema graph.

Independent attribution measured one additional FastAPI application, 276 APIRoute objects, 16 runtime modules, and approximately 11 MiB of live Python allocations per lifecycle.

## Boundary

At isolated lifespan shutdown, `release_runtime_application()` removes only the injected `app` value from private router modules and the cloned application namespace, then clears `ApplicationContext.app`. Original process-level router modules are never detached.

At startup, the context binds the current application again and `refresh_runtime_dependencies()` installs the mutable override and owning-application mapping. This permits a released application object to enter another lifespan safely.

## Fail-closed properties

- Router cloning and multi-application dependency isolation remain intact.
- No allocation threshold is increased or platform skip added.
- Shutdown occurs only after lifecycle workers and transaction scope have exited.
- The primary compatibility application is excluded from release.

## Verification

The v119 regressions verify isolated release, repeated application restart, garbage collection of multiple completed applications and runtime modules, and preservation of the primary runtime.
