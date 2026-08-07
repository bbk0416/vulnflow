# In-memory router namespace cloning

## Previous boundary

Additional `create_app()` calls reopened all 16 router source files, compiled their text, and executed the code in `SimpleNamespace` dictionaries. This provided application-specific globals but duplicated Python source execution at runtime and made isolation depend on filesystem availability and dynamic execution.

## 72.0.67 boundary

`app/router_cloning.py` now:

1. starts from already imported router modules;
2. creates one private dictionary per router and application;
3. recreates module-defined functions from their existing code objects;
4. rebuilds `APIRoute` instances from the imported route metadata;
5. injects the owning application's immutable settings and services; and
6. transfers the rebuilt routes directly to the application router.

The clone path does not open router source files and contains no `compile()` or `exec()` call. Tests also block source-file opens while cloning and verify that two applications receive distinct endpoint functions and globals dictionaries.

## Remaining limitation

This is an intermediate compatibility architecture. Router bodies continue to resolve many dependencies through a private globals mapping. A future migration should move those values to `RequestRuntime`, `get_application_context(request.app)`, or FastAPI dependencies, after which function and APIRoute cloning and private callable-cache cleanup can be removed entirely.
