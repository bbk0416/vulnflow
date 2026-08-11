# VulnFlow 72.0.74

72.0.74 is a narrow scanner asset-identity compatibility and data-integrity patch on the feature-frozen 72.0.72 line.

## Fixed

- Replace permissive hexadecimal-looking host/IP regular-expression checks with Python `ipaddress` validation.
- Keep hostnames such as `db01`, `cafe`, `face01`, and `dead.beef` as host identities instead of misclassifying them as IP addresses.
- Normalize valid IPv4/IPv6 scanner host values, including bracketed IPv6 literals, before asset-identity reconciliation.
- Treat malformed explicit Nessus `host-ip` values as warnings rather than poisoning the canonical IP identifier.
- Increase the public-CI per-group timeout guard from 300 to 360 seconds after a verified transient Windows false negative; timeout still fails the job.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- Scanner import overflow/malformed-CSV protections from 72.0.73 remain in force.
- The feature-frozen remediation closeout product scope is unchanged.
