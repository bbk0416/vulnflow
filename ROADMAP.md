# VulnFlow productization roadmap

Core 72.0.106 is the current published maintenance baseline on the 72.0.72 feature-frozen line. It packages the two scanner-import fixes discovered during the maintainer-operated Windows pilot while retaining the earlier release-integrity, security, scanner and dependency fixes. It is also the final MIT-licensed Free Public Beta baseline; future subscription-enforced product development is planned as a separately licensed commercial line.

## Phase 1 — Free Public Beta (current)

Current product: **VulnFlow Free — Public Beta**.

Goals:

- make installation and the first scanner import understandable;
- receive real/anonymized scanner compatibility reports;
- observe where import → assign → remediate → verify → close breaks down;
- collect reproducible defects and usability friction;
- learn which capabilities create repeat use.

During this phase there is no paid subscription, paid SLA or paid support product.

### Allowed code changes

Only change the core when evidence demonstrates at least one of:

1. a real scanner compatibility defect;
2. a repeated remediation-closeout workflow blocker;
3. a reproducible security/data-integrity/recovery defect;
4. a supported-platform failure;
5. a concrete requirement from a plausible target organization.

### Do not add speculatively

- generic AI assistant features;
- more dashboard widgets for feature count;
- hundreds of scanner connectors;
- ServiceNow/Teams/Slack integrations without observed demand;
- distributed PostgreSQL/SaaS architecture without a scale requirement;
- SAML/OIDC/MFA merely to look enterprise-ready;
- more proof/transparency machinery without a threat-model requirement.

## Phase 2 — Commercial readiness (separate licensed product line)

Do not add subscription enforcement to the already-published MIT baseline. Establish the commercial line separately, then define:

- the legal entity and billing/tax process;
- commercial Terms of Service / EULA as applicable;
- privacy and support policies;
- subscription cancellation/renewal rules;
- the Free Beta entitlement duration, renewal interval, grace period, and license-expiry behavior;
- the read-only/export/backup path retained after entitlement expiry;
- what is newly delivered as paid value;
- how existing MIT releases remain usable under their existing license.

Working commercial name: **VulnFlow Pro**.

The paid feature boundary must be driven by Free Beta evidence. A likely model is a maintained self-hosted subscription with commercial support, updates and buyer-requested team/enterprise capabilities rather than a forced rewrite into public SaaS. A zero-price commercial beta may still require a short-lived signed entitlement so free access can end prospectively without modifying or disabling the MIT 72.0.106 baseline.

## Phase 3 — Paid subscription

Only after commercial readiness is complete:

- publish a clear price and billing unit;
- provide a subscription agreement and cancellation path;
- ship a supported upgrade path from the Free baseline;
- separate commercial components/licensing from already-published MIT releases;
- measure activation, repeat use, support load and conversion.

## Evidence to collect now

Do not add product analytics or hidden telemetry merely to run this roadmap. Prefer explicit user feedback and repository/support signals such as:

- installation/launch issues;
- scanner/vendor/export format;
- import success/failure;
- workflow step where the user became blocked;
- whether the same team used VulnFlow for another remediation cycle;
- which missing capability would actually stop adoption.

## Current product state

```text
CORE_VERSION=72.0.106
CURRENT_EDITION=VulnFlow Free — Public Beta
CURRENT_PRICE=FREE
MIT_FREE_BASELINE=72.0.106
PAID_SUBSCRIPTION=NOT_OFFERED
FUTURE_COMMERCIAL_EDITION=SEPARATE_LICENSED_LINE_PLANNED
```
