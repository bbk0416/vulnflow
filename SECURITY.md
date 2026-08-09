# Security

## Supported version

Only the latest state of the public `main` branch and the latest tagged public release are reviewed. Older internal packages are not supported through this repository.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub Private Vulnerability Reporting for this repository. Include:

- affected version or commit;
- a minimal reproduction using synthetic data;
- expected impact;
- suggested mitigation, when available.

Do not submit real organizational vulnerability data, credentials, tokens, personal information, private keys, or classified material. There is no emergency-response SLA; VulnFlow is a personal portfolio project, not a commercial security service.

## Deployment warning

The helper scripts are intended for loopback-only evaluation. Do not expose the application remotely without independent review and at least:

- explicit authentication and authorization;
- TLS termination;
- external secret management;
- network restrictions;
- tested backup and restore procedures;
- centralized monitoring and audit retention.

Browser users are stored in SQLite with scrypt password hashes. Browser access uses opaque, HttpOnly, SameSite=Strict sessions; failed password attempts trigger a configurable temporary account lock. HTTP Basic authentication and plaintext environment-variable users are rejected. Bearer tokens remain available for automation and must be protected as secrets. VulnFlow still does not provide enterprise identity federation, MFA, a managed secrets service, or an independently audited identity implementation.

If startup cannot establish audit-chain or evidence-store integrity, VulnFlow enters an authenticated read-only recovery mode for the affected project. Normal writes and background processing for that project stop; administrators may inspect data, validate recovery bundles, run an isolated restore drill, perform an explicit restore, and then restart or explicitly recheck project integrity. This is a containment and recovery surface, not proof that damaged data is trustworthy.

Scheduled bundles are local unless `VULNFLOW_EXTERNAL_BACKUP_DIR` points to a separately mounted filesystem. External copies use an atomic rename and a SHA-256 sidecar, but neither mechanism replaces signed bundles, independent access controls, immutable retention, offline copies, or a tested organizational disaster-recovery plan. A recovery-drill pass is local point-in-time evidence and is not an RTO, RPO, availability SLA, or third-party backup attestation.

## Evidence scanning boundary

The built-in evidence scanner is a limited baseline check and reports `BASELINE_ONLY`; it is not an antivirus verdict. Administrators must record an explicit exception before downloading or approving baseline-only evidence. Integrate an external scanner before using evidence workflows in an organization.

## Data and privacy boundary

The public repository contains synthetic fixtures only. Do not commit runtime databases, `.env` files, evidence, backups, exports, tokens, private keys, or real vulnerability data. The supplied `.gitignore` blocks common generated artifacts but does not replace review before every commit.

## Advanced technical boundaries

Detailed notes about proof signing, key rotation and revocation, witness and transparency experiments, transaction boundaries, recovery barriers, and release provenance are retained in [`docs/ADVANCED_INTERNAL_VERIFICATION.md`](docs/ADVANCED_INTERNAL_VERIFICATION.md). These mechanisms are local test and integrity controls; they are not a CA identity, trusted timestamp, HSM guarantee, WORM archive, third-party certification, or legal non-repudiation system.

- On POSIX systems, project backup directories are restricted to `0700` and external bundle, sidecar, and drill-report files to `0600`; Windows access remains governed by NTFS/share ACLs.

## Collaboration integration credentials

SMTP passwords and Jira API tokens are encrypted with an operator-supplied `VULNFLOW_INTEGRATION_SECRET_KEY`. Do not commit this key, API tokens, SMTP passwords, production recipient addresses, or customer finding data. Key loss or unplanned replacement makes stored integration credentials unreadable; the current release does not provide automatic key rotation.

## Offline deployment history secrets

The sibling `.<target>.deployment-history.key` file and any `backup-key` output
contain secret HMAC material. Store backups only on encrypted offline media,
keep mode 0600, and never include them in issue reports, release archives, or
source-control history. Use `verify-audit` after restore or rotation.
