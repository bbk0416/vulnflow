# Live TLS and database schema boundaries

VulnFlow 72.0.28 keeps SQLite schema 46 and changes two implementation boundaries: database schema ownership and reverse-proxy client identity.

## Database schema modules

`app/core/database_schema.py` remains the public compatibility facade for `init_db`, `get_schema_info`, `CURRENT_SCHEMA_VERSION`, and `CURRENT_APP_VERSION`. It does not own migration SQL, trigger installation, search installation, or data backfills.

The implementation is split as follows:

| Module | Responsibility |
|---|---|
| `schema_versions.py` | current application and SQLite schema versions |
| `database_migrations.py` | ordered schema upgrades and schema-version recording |
| `database_triggers.py` | audit-trigger installation |
| `database_search.py` | FTS search installation |
| `database_backfills.py` | deterministic post-migration data backfills |
| `database_schema.py` | initialization orchestration and compatibility exports |

This change does not prove that all database operations are transactionally simple. Control and project databases remain separate SQLite files and cross-database workflows still require explicit compensation and idempotency.

## Production proxy trust boundary

The application can trust proxy headers only when it is reachable exclusively through the internal reverse-proxy network. The production Compose contract therefore keeps the application port unexposed and configures Uvicorn proxy trust for that internal hop.

The Nginx edge must replace rather than append client-supplied forwarding headers:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Port 443;
```

Using `$proxy_add_x_forwarded_for` at the public edge would preserve a caller-supplied `X-Forwarded-For` value. Once Uvicorn trusts the reverse proxy, that value could affect application-level login rate-limit identity. The 72.0.28 configuration discards it.

## Static contract check

Run:

```bash
python scripts/production_security_rehearsal.py
```

This checks source configuration only. It does not open a socket or negotiate TLS.

## Live local TLS rehearsal

Prerequisites:

- local `nginx` binary;
- local `openssl` binary;
- installed runtime requirements;
- permission to bind ephemeral loopback ports.

Run:

```bash
python scripts/live_tls_proxy_rehearsal.py \
  --json-output reports/live_tls_proxy_rehearsal_verification.json \
  --text-output reports/live_tls_proxy_rehearsal_verification.txt
```

The rehearsal creates temporary data and certificates, starts Uvicorn with `VULNFLOW_SECURITY_PROFILE=production`, starts Nginx on ephemeral loopback ports, creates a temporary database user, and performs verified HTTPS requests.

The current recorded run passed 14/14 checks. It exercised the host Nginx and Uvicorn binaries. It did not exercise Docker layer construction, Docker networking, a public certificate authority, DNS, certificate renewal, external storage, SMTP, Jira, or customer scanner exports.

## Container-equivalent rehearsal

Run:

```bash
python scripts/container_deployment_rehearsal.py --cycles 2
```

When Docker is unavailable, this rehearsal uses a non-root subprocess identity, read-only application source, split persistent storage, and repeated process startup to test a subset of container runtime contracts. A PASS is not equivalent to a Docker image build or Compose deployment.

## Target-host acceptance

Before a customer pilot, repeat the following on the target host:

1. Build the exact image from the release source.
2. Start the production Compose stack with authorized certificates.
3. Verify HTTP redirect, TLS policy, HSTS, Secure cookies, login, upload, project switching, and logout.
4. Verify proxy logs and application login-attempt records show the actual edge client identity.
5. Restart and recreate containers and confirm control DB, project DB, evidence, and backup persistence.
6. Exercise certificate renewal and rollback.
7. Exercise external backup creation and isolated restoration.

A source-level or host-process rehearsal must not be represented as completion of those target-host steps.
