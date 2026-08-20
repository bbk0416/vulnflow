# VulnFlow productization roadmap

Core 72.0.97 is the current Greenbone GMP XML result-path finding-identity patch on the 72.0.72 feature-frozen line. The project is **not abandoned**: development has moved from feature-building to free-product validation and, later, evidence-driven commercialization.

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

## Phase 2 — Commercial readiness (after business operation becomes possible)

Do not switch on billing immediately. First define:

- the legal entity and billing/tax process;
- commercial Terms of Service / EULA as applicable;
- privacy and support policies;
- subscription cancellation/renewal rules;
- what remains Free and what is newly delivered as paid value;
- how existing MIT releases are preserved.

Working commercial name: **VulnFlow Pro**.

The paid feature boundary must be driven by Free Beta evidence. A likely model is a maintained self-hosted subscription with commercial support, updates and buyer-requested team/enterprise capabilities rather than a forced rewrite into public SaaS.

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
CORE_VERSION=72.0.97
CURRENT_EDITION=VulnFlow Free — Public Beta
CURRENT_PRICE=FREE
PAID_SUBSCRIPTION=NOT_OFFERED
FUTURE_COMMERCIAL_EDITION=PLANNED_AFTER_EVIDENCE_AND_BUSINESS_READINESS
```
