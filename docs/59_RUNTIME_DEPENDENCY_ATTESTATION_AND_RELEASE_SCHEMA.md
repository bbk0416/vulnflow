# Runtime dependency attestation and release schema boundary

VulnFlow 72.0.34 introduced this boundary while keeping SQLite schema 46. This boundary distinguishes three
separate dependency claims and removes schema-version duplication from offline
release tooling.

## Dependency claims

1. **Source lock consistency** checks exact pins, direct dependency alignment,
   Docker/CI entry points, package metadata, and SBOM versions.
2. **Runtime attestation** compares the active installed distributions with the
   lock manifest packaged inside VulnFlow.
3. **Clean installation** downloads a wheelhouse, records artifact SHA-256
   values, reinstalls without an index, and runs import/HTTP smoke tests.

Passing one claim does not imply that the others passed.

## Runtime policy

```env
VULNFLOW_RUNTIME_DEPENDENCY_POLICY=off
```

Supported values:

- `off`: do not inspect installed package versions;
- `warn`: inspect and record drift without blocking startup;
- `enforce`: reject startup when an active locked package is missing or differs.

The production security profile requires `enforce`. The packaged manifest is
generated from `requirements.lock` and includes explicit conditions for the
Windows-only `colorama` package and non-Windows CPython `uvloop` package.

The manifest contains names and versions, not upstream wheel hashes. Artifact
hashes remain the responsibility of the clean wheelhouse CI report and signed
release distribution.

## Offline release schema

The application schema source is `app/core/schema_versions.py`. Source-based
release rehearsals import that value directly. The standalone offline bootstrap
cannot import the application before installation, so it reads `schemaVersion`
from the signed release distribution index after the DSSE verification command
succeeds.

This prevents a copied constant from silently falling behind future migrations.
The bootstrap report records the expected signed-index schema next to the
installed SQLite schema.

All three release paths set explicit `VULNFLOW_CONTROL_DB`,
`VULNFLOW_PROJECTS_DIR`, and `VULNFLOW_DEFAULT_PROJECT_DB` values. Their schema
checks target the default project database, not the legacy migration input.

## Limits

- Exact installed versions do not prove that the original upstream artifacts
  were trustworthy.
- The manifest does not perform an advisory vulnerability lookup.
- Linux and Windows marker handling is intentionally limited to conditions
  currently present in `requirements.lock`; generation fails on unknown marker
  expressions instead of guessing.
- Production operators still need the clean wheelhouse, Docker, TLS, backup,
  and browser acceptance gates relevant to their deployment.
