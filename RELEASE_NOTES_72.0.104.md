# VulnFlow Free — Public Beta 72.0.104

Release date: 2026-09-28

72.0.104 is a security-maintenance patch on the feature-frozen 72.0.72 line. It publishes the post-72.0.103 runtime hardening that is already validated on `main`; it does not add a product feature or change SQLite schema 46.

## Security maintenance

- Return generic 403 text for project-scope authorization failures instead of reflecting internal `PermissionError` detail such as project identifiers.
- Return generic 503 text while the restore/write barrier is active instead of reflecting internal `WriteBarrierActive` exception detail.
- Keep the existing HTTP status semantics and authorization/write-barrier behavior; only the externally returned error text is hardened.
- Update the build backend pin from `setuptools==82.0.1` to `setuptools==83.0.0`, the first patched release for GHSA-h35f-9h28-mq5c. This is a build/source-distribution hardening change, not a VulnFlow runtime dependency change.
- Preserve the existing TLS 1.2+ outbound rehearsal and exact production-example configuration checks added with the same security-hardening baseline.

## Validation contract

- Public regression collection contract: 731 tests across seven bounded groups (78 + 76 + 168 + 80 + 117 + 67 + 145), with platform-specific skips reported explicitly.
- Protected `main` requires Windows and Ubuntu Python 3.12/3.13 regression checks, application line coverage at or above 75%, clean offline wheelhouse reinstall, Docker production validation, Chromium E2E, static/dependency quality, CodeQL for Actions and Python, and Windows runtime-resilience.
- The Windows runtime-resilience check includes bounded SQLite fault/recovery, a 12-cycle runtime soak, a real localhost Uvicorn functional smoke, and 16-worker/320-request bounded HTTP read concurrency.
- The release ZIP is built from exact Git `HEAD` blobs covered by `SHA256SUMS.txt`; the builder verifies every manifest digest before packaging and re-verifies the archived members after packaging.

## Boundary

This release does not claim 24-hour endurance, sustained production-scale load capacity, rootless Docker, Kubernetes, or validation of a real external proxy/NAS/firewall/ACL target environment. External-user/customer pilot testing is intentionally outside repository acceptance and is not claimed as customer validation, WTP, or PMF evidence.

The immutable `v72.0.103` tag and release assets are not modified.
