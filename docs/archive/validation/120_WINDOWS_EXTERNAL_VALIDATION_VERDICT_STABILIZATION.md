# Windows external validation verdict stabilization

VulnFlow 72.0.60 separates product failures from unavailable Windows infrastructure and corrects two remaining validation contracts.

## Docker CLI versus Docker engine

`docker.exe` can be present while the Docker Desktop Linux engine named pipe is absent. Collection mode now probes `docker info` before Compose startup and emits a structured `unavailable` report when the engine cannot be reached. Required CI mode still exits non-zero. Image pull, build, startup, health, persistence, and proxy failures after a reachable engine remain real failures.

## Finding browser identity

The browser workflow follows the exact dashboard link and verifies the resulting URL, breadcrumb finding ID, and actual H1 product/CVE identity. It no longer waits for stale Korean copy that is not rendered by `finding.html`.

## Allocation measurement

`tracemalloc` begins before warm-up cycles. This allows allocations created during warm-up and freed later to be accounted for correctly. Warm-up samples are still omitted from the steady-state series, `reset_peak()` is applied at the measurement boundary, and the 24 MiB limit is unchanged.
