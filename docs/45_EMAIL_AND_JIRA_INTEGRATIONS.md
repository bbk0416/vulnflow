# Project email and Jira integrations

VulnFlow 72.0.19 adds optional project-scoped collaboration delivery. Configuration and delivery events live inside each project's physically separate SQLite database.

## Master key

Set a high-entropy value of at least 32 characters before enabling an integration:

```env
VULNFLOW_INTEGRATION_SECRET_KEY=<random secret>
```

The key is not written to project databases. SMTP passwords and Jira API tokens are stored only as Fernet ciphertext. Ordinary integration reads expose only whether a secret is configured. Back up and protect the key separately; losing or replacing it without migration makes existing credentials unreadable.

## Email

Administrators can configure an SMTP host, port, TLS mode, sender, recipients, and event selection. Supported notifications include workflow changes, verification requests and decisions, risk-acceptance requests and decisions, due-soon findings, and overdue findings.

Delivery uses a bounded outbox with retry backoff. Due-date reminders use a daily deduplication key so a successful or pending reminder is not recreated repeatedly on the same day.

## Jira Cloud

Administrators provide the Jira site root, account email, API token, project key, issue type, and comment event selection. An operator can create one Jira issue from a finding. Later selected VulnFlow events are appended to the linked issue as Jira comments.

The implementation targets Jira Cloud REST API v3 and Atlassian API-token authentication. It does not implement OAuth, Jira Data Center compatibility, automatic issue transitions, custom-field mapping, attachment upload, or bidirectional synchronization.

## Outbound and data boundary

Email recipients and Jira receive selected finding metadata such as identifier, product/CVE, asset, status, owner, target date, and an optional VulnFlow link. Operators must classify this data and authorize outbound delivery before enabling integrations.

Webhook and Jira HTTP traffic uses the pinned outbound boundary described below, including private-address blocking, an optional destination allowlist, DNS-pinned direct connections, and response-size limits. VulnFlow still does not provide DLP inspection, per-recipient redaction, KMS/HSM key management, automatic key rotation, or equivalent SMTP destination enforcement. Network-level egress ACLs remain an operator responsibility.

## Operations

The collaboration scheduler creates project-scoped background jobs. Delivery workers preserve failed events with bounded errors and retry retryable failures. A disabled or missing integration causes queued work to fail closed rather than silently delivering elsewhere.

## HTTP destination policy

Jira traffic uses the pinned HTTP egress boundary described in [HTTP outbound egress boundary](55_OUTBOUND_EGRESS_BOUNDARY.md). Private, loopback, link-local, metadata, and mixed DNS destinations are blocked by default. Use `VULNFLOW_OUTBOUND_HOST_ALLOWLIST=*.atlassian.net` or a narrower approved list in production. Environment proxy variables are intentionally ignored for Jira HTTP requests. SMTP is not covered by this HTTP policy and should be restricted separately.
