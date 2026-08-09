# VulnFlow 72.0.68 — First request-scoped router DI migration

VulnFlow 72.0.68 begins the staged removal of per-application endpoint cloning. The four pilot onboarding and executive-report routes now share their normal imported endpoint functions across applications and resolve the owning `ApplicationContext` through a FastAPI dependency derived from `request.app.state`.

## Changes

- Adds `app.router_dependencies.application_context` as a stable FastAPI dependency boundary that does not import `app.main`.
- Migrates the `pilot` router away from mutable module-global dependency installation.
- Keeps the remaining 15 router modules on the 72.0.67 in-memory cloning boundary while the migration proceeds in bounded groups.
- Includes the shared pilot router through FastAPI's normal router registration path and directly transfers only the remaining cloned routers.
- Adds four regression contracts for no-op dependency installation, shared endpoint identity, mixed shared/cloned runtime ownership, and concurrent two-application data isolation.
- Preserves 276 application routes and SQLite schema 46.

## Limitations

This is not the final router architecture. Fifteen router modules still use `FunctionType`, private globals dictionaries, APIRoute reconstruction, direct route transfer, and callable-classification cache cleanup. Those mechanisms remain compatibility boundaries until each router is converted to request-scoped context access.
