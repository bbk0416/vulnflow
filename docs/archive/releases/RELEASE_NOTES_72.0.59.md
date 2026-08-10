# VulnFlow 72.0.59 — Windows external validation verdict stabilization

VulnFlow 72.0.59 keeps SQLite schema 46 and adds no product features. It closes the remaining verdict defects found by the independent Windows v48 run:

- A Docker CLI with no reachable Docker Desktop Linux engine is now reported as `unavailable` in collection mode instead of as a product failure. `--require-docker` remains fail-closed for CI and release environments.
- The primary finding browser workflow now verifies the rendered `/finding/F-0001` URL, breadcrumb identity, and actual H1 product/CVE text rather than stale copy that does not exist in the template.
- `tracemalloc` starts before warm-up lifecycles so allocations created during warm-up are tracked and later frees are accounted for. Warm-up samples remain excluded from the steady-state delta, and the 24 MiB limit is unchanged.

The release adds four v118 regression tests. Production Compose still requires a running Docker Desktop engine, and customer scanner validation still requires approved anonymized input.
