# VulnFlow Free — Public Beta 72.0.103

Release date: 2026-09-27

72.0.103 is a dependency-maintenance patch on the feature-frozen 72.0.72 line. It upgrades Starlette from 1.6.0 to 1.7.0 after AnyIO 4.15 deprecated the anyio.abc.BlockingPortal alias used by Starlette 1.6.0 TestClient. No VulnFlow product feature, SQLite schema, route contract, or scanner normalization behavior changes.

## Dependency correction

- starlette==1.6.0 -> starlette==1.7.0
- FastAPI remains 0.141.1.
- AnyIO remains 4.15.0.
- Starlette 1.7.0 uses the supported anyio.from_thread.BlockingPortal path, removing the upstream deprecation warning seen in the public regression suite.
- The existing httpx2 development-test path remains enabled.

## Validation contract

The public regression collection contract remains 730 tests (78 + 76 + 168 + 80 + 117 + 67 + 144), with platform-specific skips reported explicitly. Public CI also requires the dedicated application line-coverage gate at or above 75%, dependency wheelhouse reinstall, Docker production validation, Chromium browser E2E, and static/dependency quality checks.

SQLite schema remains 46. The immutable v72.0.102 tag and release assets are not modified.
