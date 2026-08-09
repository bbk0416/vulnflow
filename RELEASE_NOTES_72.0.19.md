# VulnFlow 72.0.19 release notes

Released: 2026-08-02

## Summary

72.0.19 adds project-scoped SMTP notifications and Jira Cloud issue synchronization. Integration credentials are encrypted with an operator-supplied master key. The SQLite schema advances from 42 to 43.

## Added

- Project-specific email and Jira configuration under the administrator menu.
- SMTP delivery with STARTTLS, implicit TLS, authentication, bounded timeout, and retry handling.
- Email notifications for workflow changes, remediation verification, risk acceptance, due-soon findings, and overdue findings.
- Manual Jira issue creation from a finding detail page.
- Jira Cloud REST API v3 issue creation and follow-up comments for selected finding events.
- Encrypted integration credentials using Fernet with a key derived from `VULNFLOW_INTEGRATION_SECRET_KEY`.
- A project-scoped collaboration outbox with leases, retry backoff, daily reminder deduplication, and delivery audit events.
- Background and scheduled delivery across active project databases.
- Administrator delivery history and manual delivery trigger.

## Changed

- Integration ciphertext is no longer returned by normal repository reads or placed in template contexts.
- Failed Jira issue-creation events can be explicitly requeued after the administrator fixes configuration.
- Delivery result lookup no longer depends on the 2,000-row recent-event window.
- Jira base URLs reject embedded credentials, query strings, fragments, and non-root paths.
- External identifiers are URL-escaped as full path segments.

## Security boundary

The master key must be supplied separately and should be a high-entropy secret of at least 32 characters. It is not stored in project databases. Losing or changing it without a migration makes existing integration credentials unreadable. This release does not provide KMS-backed key rotation, OAuth for Jira, email content classification, outbound network allowlists, or tenant-isolated SaaS credentials.

## Verification

- Public core regression suite: 302 tests.
- New collaboration integration regression tests: 8.
- SQLite schema: 43.

Chromium E2E, Docker rebuild and schema-43 upgrade rehearsal, real SMTP/Jira tenant delivery, static security scanners, and long-duration external-service failure behavior are not claimed by this release.
