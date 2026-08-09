# Repository maintenance policy

## Status

VulnFlow is an early product-pilot codebase. Changes should prioritize a smaller customer-facing remediation workflow, reproducible defects, security hardening, deployment compatibility, and public-documentation accuracy. This repository does not yet represent a supported commercial service.

## Dependency updates

- Dependabot version updates run monthly.
- Minor and patch updates are grouped by ecosystem to reduce pull-request noise.
- Major version updates are not opened automatically.
- A major runtime dependency update requires a separate compatibility review.
- A change affecting FastAPI, Starlette, Uvicorn, cryptography, SQLite behavior, file upload parsing or Docker runtime behavior requires the relevant regression suite and, when applicable, a repeated Docker runtime validation.
- Security updates are handled separately from ordinary version-update grouping and take priority.

## Acceptance

A repository maintenance change must pass:

- release metadata consistency;
- public SHA-256 manifest verification;
- the 302-test public regression suite;
- architecture review;
- public submission readiness;
- Chromium workflow E2E through GitHub Actions;
- Ruff fatal checks, Bandit high/high and pip-audit.

The exact reviewed pull-request HEAD is squash-merged only after all required checks pass.

## Support boundary

The repository does not provide a commercial support SLA. Public issue creation or Discussions may be restricted. Documentation and reproducible public-code corrections may be proposed through pull requests when repository controls allow them. Security vulnerabilities must follow `SECURITY.md`.

## Release boundary

A documentation or repository-policy change does not require a new application release. A new tag is created only when application code, runtime dependencies, distributed artifacts or canonical release metadata change.
