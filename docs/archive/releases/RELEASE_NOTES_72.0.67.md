# VulnFlow 72.0.67 — In-memory router namespace cloning

VulnFlow 72.0.67 removes the isolated-router runtime path that reopened each Python router source file and executed it with `compile()` and `exec()` for every additional application instance.

The release rebuilds an application-private compatibility namespace from already imported module objects. Module-defined functions are recreated from their existing code objects with one private globals dictionary, and the 276 FastAPI routes are reconstructed from imported `APIRoute` metadata. No router source file is opened, parsed, compiled, or executed during additional `create_app()` calls.

This is a structural reduction rather than the final dependency-injection migration. Router functions still use application-private compatibility globals, and the FastAPI callable-classification cache cleanup introduced in 72.0.65 remains necessary until the routers are converted to explicit `RequestRuntime`/`Depends` access.

The SQLite schema remains 46. Route paths, operation names, request/response models, lifecycle restart behavior, and the 24 MiB Python allocation threshold are unchanged.
