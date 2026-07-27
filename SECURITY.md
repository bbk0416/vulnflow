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

HTTP Basic credentials and bearer tokens are development-oriented controls. VulnFlow does not provide enterprise identity federation, MFA, account lockout, or a managed secrets service.

## Evidence scanning boundary

The built-in evidence scanner is a limited baseline check and reports `BASELINE_ONLY`; it is not an antivirus verdict. Administrators must record an explicit exception before downloading or approving baseline-only evidence. Integrate an external scanner before using evidence workflows in an organization.

## Data and privacy boundary

The public repository contains synthetic fixtures only. Do not commit runtime databases, `.env` files, evidence, backups, exports, tokens, private keys, or real vulnerability data. The supplied `.gitignore` blocks common generated artifacts but does not replace review before every commit.

## Advanced technical boundaries

Detailed notes about proof signing, key rotation and revocation, witness and transparency experiments, transaction boundaries, recovery barriers, and release provenance are retained in [`docs/ADVANCED_INTERNAL_VERIFICATION.md`](docs/ADVANCED_INTERNAL_VERIFICATION.md). These mechanisms are local test and integrity controls; they are not a CA identity, trusted timestamp, HSM guarantee, WORM archive, third-party certification, or legal non-repudiation system.
