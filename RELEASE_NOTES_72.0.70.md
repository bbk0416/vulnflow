# VulnFlow 72.0.70 — FastAPI effective route-context validation

VulnFlow 72.0.70 corrects the Windows validation contract for FastAPI 0.140.9.
The framework represents included routers as lazy route-context branches instead
of flattening every included route into the application's direct route list.
The four request-scoped pilot routes were active; the previous 272-route result
was an introspection mismatch, not a product route loss.

This release adds a version-tolerant effective-route inventory based on FastAPI's
public `iter_route_contexts()` API, updates route lifecycle tests to separate
application-owned legacy routes from shared DI routes, and records an erratum in
the 72.0.69 documentation. Runtime routing behavior is unchanged.
