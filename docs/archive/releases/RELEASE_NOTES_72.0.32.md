# VulnFlow 72.0.32 release notes

VulnFlow 72.0.32 keeps SQLite schema 46 and closes the remaining direct HTTP
client paths used by fixed vulnerability-intelligence providers. OSV, CISA KEV,
and FIRST EPSS now use the same DNS-pinned, private-address-blocking transport
foundation as webhook and Jira HTTP traffic, with bounded JSON parsing and
provider-specific limits.

## Security boundary

- Removed production `requests.Session` creation from OSV discovery.
- Routed CISA KEV and FIRST EPSS refresh through the bounded outbound JSON layer.
- Rejects loopback, private, metadata, mixed-DNS, reserved, and other non-global
  destinations by default.
- Connects to validated IP addresses while retaining original-host TLS SNI,
  certificate validation, and HTTP `Host` semantics.
- Disables redirects and ignores process HTTP proxy environment variables.
- Adds independent OSV and intelligence response-size limits and bounded retries.
- Retains injected HTTP sessions only as a compatibility seam for deterministic
  legacy tests; production jobs do not construct them.

## Maintainability

- Split integration diagnostics into common, email, and Jira modules.
- Split scanner compatibility evaluation from report rendering.
- Added small bounded-JSON and optional-service invocation helpers.
- Kept existing public imports to avoid breaking internal callers.

## Static quality boundary

- Added a dependency-free AST audit before Ruff, Bandit, and pip-audit.
- Blocks new direct network clients, raw sockets outside approved transports,
  disabled TLS verification, `shell=True`, unapproved dynamic execution,
  unsafe temporary-file helpers, and unsafe deserialization imports.
- The audit is a narrow repository boundary, not a replacement for the
  third-party quality tools or penetration testing.

## Verification

- Public core regression tests: 397 tests in five bounded groups
  (`78 + 76 + 102 + 64 + 77`).
- Intelligence egress regression: 5/5 passed.
- Static security boundary regression: 4/4 passed.
- Production security static rehearsal: 25/25 passed.
- SQLite schema remains 46.

The preparation workspace did not call public OSV, CISA, or FIRST endpoints.
Local controlled servers verify transport behavior, not provider availability or
production rate limits. Docker, managed-browser E2E, Ruff, Bandit, and pip-audit
remain separate environment-dependent gates.
