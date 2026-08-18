# VulnFlow product edition policy

Status: Free Public Beta policy
Core release: 72.0.90

This is a product-direction document, not legal or tax advice. Commercial licensing, billing and terms must be reviewed before the first paid transaction.

## Current edition

**VulnFlow Free — Public Beta** is the currently available product edition.

- Price: free.
- Distribution: public GitHub source/release assets.
- Deployment: local/self-hosted.
- Core license for 72.0.90: MIT License.
- Billing, paid subscription, paid SLA and paid support: not currently offered.

The current Free edition exists to validate real scanner compatibility and the remediation-closeout workflow, not to simulate a commercial service before one exists.

## Product identity

VulnFlow is not positioned as a scanner or a generic exposure-management platform.

> A local-first vulnerability-remediation closeout workspace for teams that already have scanners but need a controlled, auditable path from scanner findings to verified closure.

The core workflow is:

```text
scanner export
  -> preview / validation
  -> deterministic reconciliation
  -> owner / due date / remediation
  -> verification request
  -> approval
  -> CLOSED / VERIFIED
  -> evidence / audit / closeout reporting
```

## Future commercial path

When the project can be operated commercially, a paid subscription edition may be introduced under the working name **VulnFlow Pro**.

This is a direction, not a current offer. Pricing, billing cadence, commercial terms and final feature boundaries are intentionally undecided until there is usage evidence.

Potential paid value may include areas such as:

- maintained upgrade/update channel;
- commercial support and response commitments;
- organization/team administration beyond the Free baseline;
- enterprise identity or ticketing integrations when buyers actually require them;
- advanced reporting/automation driven by observed workflows.

These items are not promises and should not be implemented merely to create a feature gap.

## MIT release boundary

The existing 72.0.72 release and the current 72.0.90 defect-patch release are distributed under the MIT License. Their existing license grants are not retroactively removed by a future commercial edition.

A future paid product may combine the MIT-licensed Free core with separately developed commercial components or may use a different licensing structure for new code where legally available. The exact commercial licensing model must be reviewed before the first paid transaction.

## Contribution boundary

Contributions accepted into this public Free repository are contributions to the MIT-licensed public core. Do not submit confidential, customer-owned or proprietary commercial code to this repository.

A future commercial component should be developed and licensed separately rather than silently changing the terms of already-published MIT releases.

## Evidence before monetization

Before deciding what belongs in a paid subscription, prefer evidence from:

1. scanner compatibility reports;
2. repeated workflow friction;
3. requests from identifiable target teams;
4. repeated use of the product;
5. concrete procurement blockers.

Do not build paid-only features solely because competitors have them.
