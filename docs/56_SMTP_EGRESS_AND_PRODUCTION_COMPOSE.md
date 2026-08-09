# SMTP egress and production Compose boundary

VulnFlow 72.0.31 keeps SQLite schema 46 and extends the fail-closed outbound destination policy to SMTP delivery and diagnostics. It also adds an actual production Docker Compose build-and-runtime rehearsal to the public CI contract.

## SMTP destination policy

SMTP endpoints are resolved immediately before connection. VulnFlow rejects the whole destination when any returned address is loopback, private, link-local, metadata, multicast, reserved, unspecified, or otherwise non-global, unless private SMTP is explicitly enabled.

```text
VULNFLOW_SMTP_ALLOW_PRIVATE_NETWORKS=0
VULNFLOW_SMTP_HOST_ALLOWLIST=smtp.example.com,*.mail.example.com
VULNFLOW_SMTP_ALLOW_PLAIN=0
```

An empty SMTP allowlist permits any public hostname. When private SMTP is enabled, the production profile requires a non-empty allowlist. Plain SMTP is disabled by default and forbidden by the production profile.

## DNS pinning and TLS identity

For STARTTLS and implicit TLS, VulnFlow:

1. resolves the configured SMTP hostname once for the attempted connection;
2. validates every returned address against the outbound policy;
3. connects directly to one of the validated IP addresses;
4. keeps the original hostname for SMTP EHLO, TLS SNI, and certificate hostname verification;
5. retries only another address from the same validated set after a transport failure.

This prevents a second DNS lookup from changing the destination after validation. SMTP authentication and mail content are sent only after the configured TLS boundary is established, except when a non-production operator explicitly enables plain SMTP.

## Message configuration validation

Email integration configuration rejects:

- invalid sender or recipient addresses;
- carriage returns or line feeds in address fields;
- unsupported security modes;
- a username without a configured password;
- plain SMTP unless explicitly enabled.

Outbound policy failures are permanent delivery failures rather than unbounded retries. DNS and network transport failures retain the bounded retry behavior.

## Live SMTP rehearsal

```bash
python scripts/smtp_egress_rehearsal.py
pytest -q tests/test_smtp_egress_v90.py
```

The live rehearsal creates a temporary local CA and STARTTLS server, then verifies ten checks including pinned-IP connection, original-host TLS SNI and certificate verification, authentication, actual SMTP DATA delivery, private-address blocking, allowlisting, and plain-SMTP rejection. It does not certify a customer relay, public DNS, enterprise PKI, or mail-delivery reputation.

## Production Compose CI rehearsal

```bash
python scripts/production_compose_rehearsal.py --require-docker \
  --json-output reports/production_compose_rehearsal.json
```

The rehearsal uses the checked-in `docker-compose.production.yml` and production Nginx configuration, but rewrites public ports to disposable loopback ports and mounts a temporary localhost certificate. When Docker is available it:

- validates `docker compose config`;
- builds and starts the current VulnFlow image and Nginx proxy;
- checks HTTPS readiness and HTTP-to-HTTPS redirection;
- authenticates through the TLS proxy with a project-scoped Bearer token;
- imports a synthetic finding;
- restarts the application container and checks named-volume persistence;
- verifies runtime UID 10001;
- verifies the application port is not published directly;
- verifies the backend Docker network is internal;
- removes the containers, volumes, temporary image, and certificate material.

The public CI job invokes the script with `--require-docker`, so Docker absence or Compose failure fails that job. In the workspace used to prepare 72.0.31, the Docker command was unavailable; therefore no local current-image Docker PASS is claimed. Static topology tests and the mandatory CI command are included, but a CI run must complete before citing the Compose runtime result.

## Remaining limitations

- Internal SMTP relays require explicit private-network permission and an allowlisted host; network firewall rules remain necessary.
- OSV, CISA KEV, and FIRST EPSS use fixed upstream services and are outside this administrator-configured SMTP/HTTP destination policy.
- The Compose rehearsal uses a temporary self-signed certificate and does not verify public DNS, ACME renewal, customer storage drivers, external backup media, or a 24-hour endurance run.
- This boundary is not a penetration test or production approval.
