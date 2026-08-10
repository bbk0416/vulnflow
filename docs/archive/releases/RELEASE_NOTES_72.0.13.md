# VulnFlow 72.0.13 — Tag alignment and metadata consistency

VulnFlow 72.0.13 is a patch release that brings the public release tag forward to the current validated `main`. It includes the SBOM dependency-root correction and the release-metadata consistency gate merged after `v72.0.12`.

## Included corrections

- CycloneDX application dependency root aligned with the canonical version;
- standard-library consistency check for `VERSION`, package metadata, application metadata, citation, Docker tag, lock headers, and CycloneDX references;
- consistency check executed in public CI and represented in submission readiness;
- SHA-256 public manifest regenerated for the patch release.

## Runtime impact

This release does not change vulnerability-management workflows, database schema, authentication behavior, queue behavior, restore behavior, or Docker runtime configuration beyond the visible application version.

The Windows Docker Desktop validation recorded for `72.0.12` remains the runtime evidence for this release because the intervening changes are SBOM, CI, documentation, manifest, and version metadata only.

## Automated acceptance

- release metadata consistency: 11/11;
- public regression tests: 243;
- public submission readiness: 25/25;
- Ubuntu and Windows on Python 3.12 and 3.13;
- Chromium browser E2E;
- architecture and manifest verification;
- Ruff fatal checks, Bandit high/high, and pip-audit.

## Limitations

- single-host SQLite architecture;
- no customer deployment, production SLA, or measured workflow-time reduction;
- no 24-hour endurance or Windows runtime-snapshot verification;
- no OIDC, SAML, MFA, PostgreSQL, or multi-tenant SaaS support;
- all repository and validation data remains synthetic.

## Source alignment

- pre-release source baseline: `29612061431ea3d691c85eae110e99d37785094b`;
- previous release tag retained unchanged: `v72.0.12`;
- new release tag: `v72.0.13`.
