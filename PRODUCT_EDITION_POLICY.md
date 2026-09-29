# VulnFlow product edition policy

Status: Free Public Beta policy
Core release: 72.0.106

This is a product-direction document, not legal or tax advice. Commercial licensing, billing and terms must be reviewed before the first paid transaction.

## Current edition

**VulnFlow Free — Public Beta** is the currently available product edition.

- Price: free.
- Distribution: public GitHub source/release assets.
- Deployment: local/self-hosted.
- Core license for 72.0.106: MIT License.
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

## Commercial transition boundary

**72.0.106 is the final MIT-licensed Free Public Beta baseline.** Existing copies and previously published MIT releases keep the rights already granted by the MIT License. A later commercial decision does not revoke, disable, or convert those existing MIT rights.

Future product development that is intended to support subscription enforcement must be developed and distributed separately from this public MIT repository under separate commercial terms. The working commercial name remains **VulnFlow Pro**.

The commercial edition may initially be offered at a zero price during a time-limited Free Beta. Zero price does not mean a perpetual license. Before activation, the applicable commercial terms must state that:

- Free Beta access is a revocable, time-limited entitlement for the commercial edition;
- the entitlement may require periodic renewal from a licensing service;
- the maintainer may stop issuing or renewing Free Beta entitlements when the commercial edition moves to paid availability;
- after the current entitlement and disclosed grace period expire, write/operate functions may become unavailable unless a valid paid entitlement is present;
- existing customer data is not remotely deleted as part of a license transition;
- a license-expired installation should retain a bounded read-only/export/backup path so users can retrieve their data.

A future commercial edition may provide maintained updates, support commitments, organization/team administration, enterprise integrations, reporting, or automation when actual users justify those capabilities. These are not promises and should not be implemented merely to manufacture a feature gap.

## MIT release boundary

The existing 72.0.72 release, the 72.0.102 scanner-correctness release, the 72.0.103 dependency-maintenance release, the 72.0.104 security-maintenance release, the 72.0.105 maintenance release, and **72.0.106** are distributed under the MIT License. Their existing license grants are not retroactively removed by a future commercial edition.

The public repository remains the historical and maintenance home of that MIT baseline. Proprietary subscription enforcement must not be added here as a mechanism to retroactively restrict already-published MIT copies. Commercial code and licensing infrastructure should be maintained separately. The exact commercial license, billing, consumer/business terms, tax treatment, and cancellation/refund rules must be reviewed before the first paid transaction.

## Contribution boundary

Contributions accepted into this public Free repository are contributions to the MIT-licensed public core. Do not submit confidential, customer-owned or proprietary commercial code to this repository.

A future commercial component and its license-enforcement service should be developed and licensed separately rather than silently changing the terms of already-published MIT releases.

## Evidence before monetization

Before deciding what belongs in a paid subscription, prefer evidence from:

1. scanner compatibility reports;
2. repeated workflow friction;
3. requests from identifiable target teams;
4. repeated use of the product;
5. concrete procurement blockers.

Do not build paid-only features solely because competitors have them.
