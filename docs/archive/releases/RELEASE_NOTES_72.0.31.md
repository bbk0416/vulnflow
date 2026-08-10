# VulnFlow 72.0.31 release notes

VulnFlow 72.0.31 keeps SQLite schema 46, extends pinned outbound destination controls to SMTP, and adds an actual production Docker Compose runtime rehearsal as a mandatory public CI gate.

## Security changes

- Added DNS-pinned SMTP connections for STARTTLS and implicit TLS while preserving the configured hostname for SNI and certificate verification.
- Blocked loopback, private, link-local, metadata, mixed public/private DNS, and other non-global SMTP destinations by default.
- Added exact and wildcard SMTP hostname allowlisting.
- Disabled plain SMTP by default and prohibited it in the production security profile.
- Required an SMTP allowlist when a production deployment explicitly permits private-network relays.
- Rejected sender and recipient header injection and malformed addresses.
- Classified SMTP destination-policy failures as permanent rather than repeatedly retrying an unsafe destination.

## Deployment verification

- Added `scripts/production_compose_rehearsal.py` to build and start the checked-in production Compose/Nginx topology when Docker is available.
- The rehearsal checks HTTPS readiness, redirect behavior, authenticated proxy access, synthetic import, container restart, named-volume persistence, UID 10001, unpublished application port, and an internal backend network.
- Public CI now runs the rehearsal with `--require-docker`; Docker absence or runtime failure fails that job.
- The preparation workspace did not provide a Docker command, so this release does not claim a local current-image Compose PASS. The actual CI result must be cited separately after it runs.

## Verification completed in the preparation workspace

- Public core regression tests: 388 tests in five bounded groups (`78 + 76 + 93 + 64 + 77`).
- Live temporary-CA SMTP STARTTLS rehearsal: 10/10.
- Production security static contract: 23/23.
- Existing outbound HTTPS, live Nginx/Uvicorn TLS, runtime fault, lifecycle soak, schema upgrade, and scanner fixture rehearsals retained.
- SQLite schema remains 46.

## Known limits

- No authorized customer SMTP relay, Jira tenant, Nessus export, or Greenbone export was supplied.
- Docker Compose runtime was not executed in the preparation workspace because Docker was unavailable.
- Public DNS, enterprise PKI, certificate renewal, external backup media, and 24-hour endurance remain deployment-specific validation work.
