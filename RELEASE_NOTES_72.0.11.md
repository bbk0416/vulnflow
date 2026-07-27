# VulnFlow 72.0.11 — Public repository release

VulnFlow is a local FastAPI and SQLite vulnerability-operations project. It connects synthetic scanner findings to asset normalization, explainable prioritization, remediation tracking, approvals, evidence, audit, backup, and recovery.

## Public release contents

- complete application source and synthetic demo data;
- representative dashboard, finding-detail, and asset-inventory screenshots;
- architecture and operating documentation;
- 230 public representative tests;
- Docker and local Python launch configuration;
- CycloneDX SBOM;
- explicit scope, security, support, and contribution policies.

## Verification summary

The public package was independently extracted and checked for safe ZIP paths, CRC integrity, internal hashes, prohibited runtime data, and obvious personal or secret values. The included representative suite passed 230 tests.

The separately maintained internal submission baseline reported 555 automated tests and 79.96% application line coverage. Full release rehearsal artifacts, runtime snapshots, DSSE envelopes, and internal journals are intentionally excluded from the public repository.

## Important limitations

- single-host SQLite architecture;
- no OIDC, SAML, MFA, PostgreSQL, or multi-tenant SaaS support;
- not a vulnerability scanner or autonomous impact-analysis engine;
- no production SLA or customer pilot claim;
- all included data is synthetic;
- actual Docker-engine, Windows snapshot, and 24-hour endurance validation remain separate work.
