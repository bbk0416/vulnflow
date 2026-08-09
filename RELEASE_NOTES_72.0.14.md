# VulnFlow 72.0.14

This patch replaces plaintext browser credentials with database-backed users and opaque sessions.

## Authentication changes

- Browser passwords are stored only as scrypt hashes in SQLite.
- Browser login uses HttpOnly, SameSite=Strict session cookies; raw session tokens are never stored.
- Failed logins trigger configurable temporary account lockout, and an expired lock begins a fresh failure window.
- Administrators can create, disable, unlock, reset passwords, and revoke sessions from `/admin/users`.
- The first administrator is created with `python -m scripts.manage_users`; CLI account changes are written to the audit chain.
- HTTP Basic and plaintext `VULNFLOW_USERS_JSON`, `VULNFLOW_AUTH_USER`, and `VULNFLOW_AUTH_PASSWORD` are rejected.
- Bearer tokens remain available for automation APIs.

## Database

Schema version 41 adds `app_users`, `auth_sessions`, and `auth_login_attempts` with bounded retention and session revocation.

## Compatibility

Existing databases migrate automatically. Deployments using plaintext environment users must create database users before upgrading.

## Verification

The 264 core regression tests pass. Browser E2E remains present, but this workspace could not execute it because managed Chromium blocked loopback navigation. Ruff, Bandit, pip-audit, and a schema-41 Docker rehearsal were not run here.
