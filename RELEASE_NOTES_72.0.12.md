# VulnFlow 72.0.12 — Docker runtime validation maintenance

VulnFlow 72.0.12 is a maintenance release of the local FastAPI and SQLite vulnerability-operations project. It does not add a new product feature or claim production deployment.

## What changed

- records an actual Windows Docker Desktop build and runtime validation;
- updates the canonical application and package version from 72.0.11 to 72.0.12;
- aligns the Docker tag, citation metadata, lock-file headers, CycloneDX metadata, public verification record, and SHA-256 manifest;
- retains the dependency audit fixes and final public-quality work already merged into `main`.

## Docker runtime validation

The shipped `Dockerfile` and `docker-compose.yml` were used without a separate development image. The validation passed:

- clean clone and `docker compose build --pull`;
- readiness endpoint;
- non-root image and runtime UID 10001;
- SQLite schema version 40;
- synthetic finding import through the API;
- persistence after Compose restart;
- persistence after container removal and recreation with the same named volume;
- transactional SQLite backup;
- restore into a new named volume and successful readiness.

The validation target was pre-release main commit `91da24eb6f09ab1b187afeae6092fd68ca59114a`. The 72.0.12 release changes release metadata and documentation after that runtime run; GitHub Actions remains the acceptance gate for the release commit.

## Automated verification retained

- 243 public representative regression tests;
- three Chromium workflow E2E tests;
- Ubuntu and Windows on Python 3.12 and 3.13;
- architecture boundary and public manifest checks;
- Ruff fatal rules, Bandit high/high, and pip-audit.

## Limitations

- single-host SQLite architecture;
- no OIDC, SAML, MFA, PostgreSQL, or multi-tenant SaaS support;
- no customer deployment, production SLA, or measured workflow-time reduction;
- no 24-hour endurance or Windows runtime-snapshot verification;
- all repository and validation data is synthetic.
