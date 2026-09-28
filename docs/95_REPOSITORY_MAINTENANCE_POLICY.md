# Repository maintenance policy

## Status

VulnFlow is a public-beta local vulnerability-remediation codebase. Changes should prioritize a smaller operator-facing remediation workflow, reproducible defects, security hardening, deployment compatibility, and public-documentation accuracy. This repository does not yet represent a supported commercial service.

## Dependency updates

- Dependabot version updates run monthly.
- Minor and patch updates are grouped by ecosystem to reduce pull-request noise.
- Major version updates are not opened automatically.
- A major runtime dependency update requires a separate compatibility review.
- A change affecting FastAPI, Starlette, Uvicorn, cryptography, SQLite behavior, file upload parsing or Docker runtime behavior requires the relevant regression suite and, when applicable, a repeated Docker runtime validation.
- Security updates are handled separately from ordinary version-update grouping and take priority.

## Validation ownership

External-user or customer pilot testing is intentionally out of scope for this repository. Repository acceptance is based on maintainer-operated, reproducible checks that can be executed directly in local, CI, browser, container, and target-host environments. Real-customer files, customer environments, WTP, PMF, or external-user feedback are not required to close repository work and must not be claimed unless independently provided and reproduced.

## Acceptance

A repository maintenance change must pass:

- release metadata consistency;
- public SHA-256 manifest verification;
- the 731-test public regression suite;
- architecture review;
- public submission readiness;
- Chromium workflow E2E through GitHub Actions;
- application line coverage at or above 75% on Ubuntu/Python 3.13;
- clean offline wheelhouse reinstall from the pinned dependency locks;
- Docker schema-upgrade and production Compose validation on Ubuntu 24.04;
- Ruff fatal checks, Bandit high/high and pip-audit;
- the bounded SQLite fault/recovery rehearsal on Windows/Python 3.13;
- the 12-cycle runtime stability soak on Windows/Python 3.13;
- the real localhost Uvicorn functional smoke plus 16-worker/320-request bounded HTTP read concurrency on Windows/Python 3.13;
- GitHub CodeQL default-setup analyses for Actions and Python.

The exact reviewed pull-request HEAD is squash-merged only after all required checks pass. The protected `main` branch requires pull requests and the named public CI status checks; force-push and deletion are disabled.

## Support boundary

The repository does not provide a commercial support SLA. Public issue creation or Discussions may be restricted. Documentation and reproducible public-code corrections may be proposed through pull requests when repository controls allow them. Security vulnerabilities must follow `SECURITY.md`.

## Release boundary

A documentation or repository-policy change does not require a new application release. A new tag is created only when application code, runtime dependencies, distributed artifacts or canonical release metadata change.
