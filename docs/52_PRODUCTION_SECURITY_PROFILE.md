# Production security profile

VulnFlow 72.0.32 adds `VULNFLOW_SECURITY_PROFILE=production`. The application
refuses startup when the minimum HTTPS, session, signing, evidence scanning,
and external backup contract is incomplete.

Required production controls include:

- HTTPS `VULNFLOW_PUBLIC_BASE_URL` and Secure cookies
- demo and local administrator fallback disabled
- user-agent or strict session binding plus an idle timeout
- explicit project scope on every configured Bearer token
- `VULNFLOW_RUNTIME_DEPENDENCY_POLICY=enforce` so installed runtime versions match the packaged lock manifest
- signed audit records and signed recovery bundles
- an explicit persistent cursor signing key
- scheduled recovery bundles copied to an external backup directory
- evidence scanning with clean-file enforcement

Use `docker-compose.production.yml` with deployment-specific `.env.production`
and certificate files. Run the static repository contract check with:

```bash
python scripts/production_security_rehearsal.py
```

This check does not execute Docker or prove real TLS, DNS, backup storage, or
external integrations. A separate host-process rehearsal is available with
`scripts/live_tls_proxy_rehearsal.py`; it exercises local Nginx and Uvicorn but
still does not prove Docker networking, public PKI, certificate renewal, or
external services. See `docs/53_LIVE_TLS_AND_SCHEMA_BOUNDARIES.md`.
## Outbound HTTP requirements

Production refuses `VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS=1`. When `VULNFLOW_WEBHOOKS_JSON` configures an environment webhook, `VULNFLOW_OUTBOUND_HOST_ALLOWLIST` must also be present. Jira and webhook requests use DNS-pinned direct connections, do not follow redirects, ignore environment proxy variables, and enforce `VULNFLOW_OUTBOUND_MAX_RESPONSE_BYTES`. OSV, CISA KEV, and FIRST EPSS use the same network foundation with `VULNFLOW_OSV_MAX_RESPONSE_BYTES` and `VULNFLOW_INTEL_MAX_RESPONSE_BYTES`. See [HTTP outbound egress boundary](55_OUTBOUND_EGRESS_BOUNDARY.md).


## Fixed intelligence providers

The production example allowlist includes `api.osv.dev`, `www.cisa.gov`, and `api.first.org`. OSV, KEV, and EPSS use the same private-address rejection and pinned-IP HTTP foundation as the administrator-configured HTTP integrations, with separate response-size limits. Replacing a provider endpoint requires an explicit allowlist update.
