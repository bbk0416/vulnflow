# Intelligence egress and service boundaries

VulnFlow 72.0.32 keeps SQLite schema 46 and extends the pinned outbound HTTP
transport to fixed vulnerability-intelligence providers. CISA KEV, FIRST EPSS,
and OSV production requests no longer create ordinary `requests.Session`
connections or inherit process proxy settings.

## Covered providers

The runtime uses the common outbound policy for:

- CISA Known Exploited Vulnerabilities catalog retrieval;
- FIRST EPSS batch score retrieval;
- OSV querybatch, pagination, and vulnerability-record retrieval.

Webhook and Jira delivery first received this boundary in 72.0.30. SMTP received
a separate pinned STARTTLS/SMTPS transport in 72.0.31.

## Connection policy

For each request VulnFlow:

1. validates HTTPS and the normalized destination;
2. resolves every address returned for the host;
3. rejects the host when any address is loopback, private, link-local,
   metadata, reserved, multicast, unspecified, or otherwise non-global;
4. connects to a validated IP address directly;
5. retains the original hostname for TLS SNI, certificate validation, and the
   HTTP `Host` header;
6. ignores process-level HTTP proxy environment variables;
7. disables redirects;
8. caps the response before JSON parsing.

This prevents the fixed providers from becoming an unreviewed SSRF path and
reduces DNS-rebinding exposure between validation and connection.

## Production allowlist

The checked-in production example includes the fixed providers explicitly:

```text
VULNFLOW_OUTBOUND_HOST_ALLOWLIST=api.osv.dev,www.cisa.gov,api.first.org,*.atlassian.net
```

An installation that replaces a provider URL must add the exact replacement
host to the approved allowlist. Private-network access remains disabled in the
production profile.

## Bounded responses and retries

```text
VULNFLOW_OSV_MAX_RESPONSE_BYTES=4194304
VULNFLOW_INTEL_MAX_RESPONSE_BYTES=8388608
VULNFLOW_INTEL_TIMEOUT_SECONDS=30
VULNFLOW_INTEL_RETRIES=3
```

OSV and intelligence responses are bounded independently. HTTP 429, selected
5xx responses, and transport failures receive limited retries. Policy failures,
invalid JSON, unexpected response shapes, and oversized bodies do not enter an
unbounded retry loop. An empty or malformed KEV catalog is rejected rather than
clearing existing KEV state.

## Service-boundary split

The release also reduces near-limit service modules without changing their
public imports:

- integration diagnostics are split into common, email, and Jira modules;
- scanner compatibility evaluation and report rendering are separate modules;
- optional service invocation compatibility is isolated in a small helper;
- bounded JSON transport is owned by `app/services/outbound_json.py`.

## Built-in static boundary audit

`scripts/static_security_boundary_audit.py` is dependency-free and runs before
Ruff, Bandit, and pip-audit. It rejects newly introduced direct network clients,
unsafe TLS disabling, shell execution, unapproved dynamic execution, raw socket
connections outside the approved transports, unsafe temporary-file helpers,
and unsafe deserialization imports.

This audit is intentionally narrow. It is not a substitute for Ruff, Bandit,
pip-audit, penetration testing, or review of third-party dependencies.

## Verification

```bash
python scripts/static_security_boundary_audit.py
pytest -q tests/test_static_security_boundary_v92.py
pytest -q tests/test_intelligence_egress_v91.py
python scripts/osv_discovery_smoke.py
python scripts/osv_http_smoke.py
```

The regression tests exercise default loopback rejection, explicit test-only
private access, exact host allowlisting, bounded responses, and real local OSV,
KEV, and EPSS traffic through the pinned transport.

## Limits

The preparation workspace did not call the public OSV, CISA, or FIRST services.
The tests use disposable local servers and controlled resolver results. They
validate the transport contract, not provider availability, production rate
limits, or vendor certification. Docker, Chromium E2E, Ruff, Bandit, and
pip-audit results must be evaluated independently where those tools are
available.
