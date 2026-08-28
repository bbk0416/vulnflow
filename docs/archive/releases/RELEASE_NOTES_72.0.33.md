# VulnFlow 72.0.33 release notes

VulnFlow 72.0.33 keeps SQLite schema 46 and strengthens distribution
installability, runtime image minimization, and browser-independent workflow
coverage. It does not add a product feature or claim a completed customer
pilot.

## Changes

- adds a clean dependency wheelhouse CI rehearsal that downloads pinned wheels,
  records per-run SHA-256 values, reinstalls with `--no-index`, checks exact
  installed versions, imports the application, and runs focused HTTP tests;
- separates static dependency-lock consistency from active-interpreter version
  verification;
- removes Requests and its Requests-only transitive packages from the runtime
  dependency set while retaining them in the development lock;
- removes the full source `scripts/` tree from the production image and copies
  only reviewed offline administration commands;
- adds server-rendered HTTP E2E coverage for workflow update, import preview and
  apply, search, and risk-acceptance approval separation;
- retains Chromium E2E as a separate mandatory CI job.

## Verification in the preparation workspace

The public core suite contains 405 tests in five bounded groups. The three
Chromium tests remain separately collected. The local browser was blocked by
managed policy before reaching VulnFlow, and the configured package index did
not contain the exact locked FastAPI release. Those two unavailable checks are
reported as limitations, not passes.

See [Dependency install and runtime image boundary](../../58_DEPENDENCY_INSTALL_AND_RUNTIME_IMAGE_BOUNDARY.md).
