# VulnFlow 72.0.50 — Challenge-bound external-validation evidence

SQLite schema remains 46.

This release closes an evidence replay boundary in the signed external
validation exchange. Earlier releases authenticated a response against a signed
request but did not embed that request identity into the evidence collection
report itself. A valid evidence directory from an older request could therefore
be reused when signing a later response for the same source release.

72.0.50 adds a signed-request binding to the collector aggregate, records the
collection start and completion times, and requires the evidence to have been
collected within the signed request window. The response signer and detached
verifier both recompute the expected request binding.

Rejected cases include:

- evidence collected for another request ID or nonce;
- evidence whose request JSON or request signature differs;
- unbound evidence collected outside `execute-request`;
- collection before the signed request or after request expiry;
- collection completing after response creation;
- response statements whose binding digest or collection window differs from
  the embedded aggregate.

The public core contract increases from 573 to 579 tests. Three Chromium E2E
tests remain outside the core count. No product workflow or database schema was
added.
