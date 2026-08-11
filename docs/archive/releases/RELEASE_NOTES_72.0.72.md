# VulnFlow 72.0.72 — Pilot completion freeze

This release is the code-completion candidate for the current local vulnerability-operations product scope.

## Product changes

- Scanner data is now a required condition for the pilot launch center to report `launch_ready`.
- The remediation-verification screen is an action-oriented queue with Korean status/method labels, state counters, evidence counts, and direct finding links.
- Primary navigation opens the pending verification queue instead of a mixed history view.
- README quick-start now delegates installation to the locked platform launchers rather than instructing users to install `requirements.txt` manually.

## Release-blocking CI closure

- Upgraded the locked `cryptography` runtime baseline from 48.0.1 to 50.0.0 after the public dependency audit reported newly disclosed advisories.
- Kept the signed offline deployment bootstrap Linux/CPython-only and aligned the one missed POSIX filesystem test with the existing selective Windows skip contract.
- Split the production Compose edge onto a normal `frontend` network while keeping the VulnFlow application isolated on the internal `backend` network; the proxy is dual-homed and remains the only published service.
- Added production Compose failure diagnostics and pre-created the external-backup mount point with the non-root runtime ownership.

## Completion policy

After 72.0.72, new features are frozen for this pilot scope. Subsequent changes should be limited to defects found by real scanner compatibility work, practitioner pilot use, or release-blocking security/reliability issues.

## Compatibility

- SQLite schema: 46 (unchanged)
- Existing imports, APIs, approvals, evidence, backup/recovery and integration contracts remain compatible.
- The internal 72.x identifier is retained for lineage; it is not a public major-version count.
