# VulnFlow 72.0.30 release notes

VulnFlow 72.0.30 keeps SQLite schema 46 and introduces a pinned outbound HTTP boundary for webhook and Jira traffic.

## Security changes

- Blocks loopback, private, link-local, metadata, multicast, reserved, and other non-global HTTP destinations by default.
- Rejects mixed public/private DNS answers rather than selecting only a public address.
- Pins each request to a validated IP while preserving the original hostname for TLS SNI, certificate verification, and the HTTP `Host` header.
- Ignores environment HTTP proxy variables for webhook and Jira delivery.
- Adds an optional exact/wildcard hostname allowlist.
- Adds a bounded response-body limit with a 1 MiB default.
- Disallows webhook URL credentials, fragments, and effectively empty event lists.
- Makes private HTTP egress a production security-profile failure.
- Requires a host allowlist when production environment webhooks are configured.

## Verification

- Public core regression tests: 377 tests in five bounded groups (`78 + 76 + 82 + 64 + 77`).
- Live outbound TLS egress rehearsal: 9/9 checks passed.
- Bounded twelve-cycle runtime soak: passed with 28/28 durable jobs and 16 accepted HMAC webhooks.
- SQLite schema remains 46; no database migration is introduced.

## Scope boundary

This release protects administrator-configured webhook and Jira HTTP traffic. SMTP and fixed intelligence-provider transports are not moved to the pinned HTTP client in this release. The live rehearsal uses a temporary local CA and loopback endpoint, not a customer network or Jira tenant.
