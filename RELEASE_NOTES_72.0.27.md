# VulnFlow 72.0.27

## Production security boundary

- Adds `development`, `pilot`, and fail-closed `production` security profiles.
- Production startup requires HTTPS public URL, Secure cookies, session binding and idle timeout, signed audit and backup data, persistent cursor key, scheduled external backups, and evidence scanning.
- Bearer API tokens without an explicit `projects` scope now have no project access.
- Bearer administrators no longer bypass token project scopes.
- Adds user-agent or strict session binding, idle-session revocation, and schema 46 `last_seen_at` state.
- Adds a production Docker/Nginx TLS configuration contract and a static rehearsal script.

## Limits

The included production deployment rehearsal validates repository configuration only. It does not prove a Docker image build, real certificate chain, DNS, external backup mount, SMTP/Jira tenant, or long-running production workload.
