# Repository maintenance policy

## Status

VulnFlow is maintained as a frozen portfolio baseline. New product features are not planned. Maintenance is limited to reproducible defects, security advisories, dependency compatibility and public-documentation corrections.

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
- the 243-test public regression suite;
- architecture review;
- public submission readiness;
- Chromium workflow E2E through GitHub Actions;
- Ruff fatal checks, Bandit high/high and pip-audit.

The exact reviewed pull-request HEAD is squash-merged only after all required checks pass.

## Support boundary

The repository is not a commercial support channel. Public issue creation or Discussions may be restricted. Documentation and reproducible public-code corrections may be proposed through pull requests when repository controls allow them. Security vulnerabilities must follow `SECURITY.md`.

## Release boundary

A documentation or repository-policy change does not require a new application release. A new tag is created only when application code, runtime dependencies, distributed artifacts or canonical release metadata change.
