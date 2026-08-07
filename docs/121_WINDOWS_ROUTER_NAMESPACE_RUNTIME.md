# Windows router namespace runtime

VulnFlow 72.0.61 removes the final Windows-specific router-runtime retention without weakening application isolation.

## Observed boundary

On CPython 3.13 for Windows, completed isolated applications were garbage-collected but framework schema metadata retained each synthetic `ModuleType` used to host cloned router globals. Three additional lifecycles left 48 module objects. The same source contract did not reproduce on Linux, so the public regression must not rely on platform-specific module garbage collection.

## Runtime contract

Each isolated application still compiles the 16 router sources into a separate globals mapping. A lightweight `SimpleNamespace` owns that mapping instead of `ModuleType`. The namespace is not inserted into `sys.modules`; route functions still resolve settings and service hooks from their own globals mapping.

Lifespan shutdown removes only the owning application reference. A later lifespan rebinds the application and mutable overrides. The process-level compatibility routers remain ordinary imported modules.

## Acceptance

- no synthetic runtime `ModuleType` objects are created;
- isolated router names never appear in `sys.modules`;
- the same application can restart after shutdown;
- repeated isolated lifecycles release application weak references;
- the 24 MiB Python allocation limit remains unchanged.

The bounded public runner also removes inherited `FORCE_COLOR` so ANSI warnings cannot corrupt JSON-only administration CLI output.
