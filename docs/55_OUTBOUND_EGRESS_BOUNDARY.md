# HTTP outbound egress boundary

VulnFlow 72.0.30 keeps SQLite schema 46 and adds a fail-closed HTTP transport for webhook and Jira delivery. This change addresses server-side request forgery and DNS-rebinding exposure in administrator-configured HTTP destinations. This document covers the 72.0.30 administrator-configured HTTP boundary. SMTP gained a separate pinned transport in 72.0.31. VulnFlow 72.0.32 applies the same DNS-pinned HTTP foundation to the fixed OSV, CISA KEV, and FIRST EPSS providers; see [Intelligence egress and service boundaries](57_INTELLIGENCE_EGRESS_AND_SERVICE_BOUNDARIES.md).

## Default policy

The following destinations are rejected unless private networking is explicitly enabled:

- loopback and localhost names
- RFC1918 and other non-global IPv4 addresses
- IPv6 loopback, unique-local, link-local, multicast, and other non-global addresses
- cloud metadata and link-local destinations such as `169.254.169.254`
- hostnames returning a mixture of public and blocked addresses
- URLs containing user information, fragments, control characters, whitespace, or backslashes

`VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS=0` is the safe default and is mandatory in the production security profile.

## DNS pinning

A preflight DNS check alone is not sufficient because a hostname can resolve differently between validation and connection. VulnFlow therefore:

1. resolves the destination immediately before every request;
2. rejects the entire hostname if any returned address violates policy;
3. connects directly to one of the validated IP addresses;
4. sends the original HTTP `Host` value;
5. uses the original hostname for TLS SNI and certificate hostname validation;
6. never follows redirects;
7. ignores process-level HTTP proxy environment variables for these requests.

This pins each request to the validated address set while preserving normal HTTPS certificate verification.

## Host allowlist

`VULNFLOW_OUTBOUND_HOST_ALLOWLIST` accepts comma-separated exact hosts and wildcard suffixes.

```text
VULNFLOW_OUTBOUND_HOST_ALLOWLIST=*.atlassian.net,hooks.example.com
```

`*.example.com` permits `hooks.example.com` but does not permit the apex `example.com`. An empty allowlist permits any public hostname. In the production profile, configured environment webhooks require a non-empty allowlist.

## Response boundary

`VULNFLOW_OUTBOUND_MAX_RESPONSE_BYTES` limits response bodies held in memory. The default is 1 MiB and the application clamps the value between 4 KiB and 10 MiB. Oversized responses fail permanently rather than entering an unbounded retry loop.

## Local development

The bounded runtime soak uses a disposable loopback webhook receiver and explicitly sets:

```text
VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP=1
VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS=1
```

Do not copy those values into a production deployment.

## Verification

```bash
python scripts/outbound_egress_rehearsal.py
pytest -q tests/test_outbound_egress_v89.py
```

The live rehearsal creates a temporary local CA and HTTPS endpoint, overrides DNS only inside the process, and verifies:

- connection to the validated IP instead of a second DNS lookup;
- original-host TLS SNI and certificate validation;
- original `Host` header and path/query preservation;
- Basic authentication transport;
- independence from `HTTPS_PROXY`;
- default private-network blocking;
- hostname allowlist enforcement.

## Related SMTP boundary

VulnFlow 72.0.31 adds a separate SMTP transport with the same all-address validation and pinned-IP principle while retaining original-host TLS verification. See [SMTP egress and production Compose boundary](56_SMTP_EGRESS_AND_PRODUCTION_COMPOSE.md). VulnFlow 72.0.32 then applies the bounded JSON transport to OSV, CISA KEV, and FIRST EPSS. These fixed providers share the network policy but retain provider-specific response limits and validation.
