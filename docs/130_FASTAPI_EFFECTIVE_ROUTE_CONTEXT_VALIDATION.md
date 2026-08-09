# FastAPI effective route-context validation

VulnFlow 72.0.70 corrects the validation model used for request-scoped routers.
FastAPI 0.140.9 keeps an included router as a lazy route-context branch. Direct
inspection therefore sees 272 application-owned legacy `APIRoute` objects,
while the effective routing inventory contains those 272 routes plus the four
shared pilot routes.

The application now exposes a version-tolerant effective-route inventory helper.
It uses FastAPI's public `iter_route_contexts()` API where available and falls
back to direct routes on older FastAPI versions that flatten included routers.

Lifecycle assertions distinguish application-owned legacy route graphs, which
must be released with each isolated app, from shared request-scoped pilot routes,
which intentionally remain on the imported router and are reused across apps.
HTTP concurrency tests remain the product-level isolation contract.
