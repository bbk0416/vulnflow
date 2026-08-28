# Challenge-bound external-validation evidence

VulnFlow 72.0.50 prevents an older valid evidence directory from being attached
to a new signed external-validation request.

## Previous boundary

The v37-v39 response statement was bound to the retained signed request, and
all evidence bytes were covered by the operator signature. The aggregate
`external-validation-report.json` itself did not identify the request that
caused collection. A runner could therefore reuse evidence collected for an
older challenge and create a new response signature for a later challenge.

## Request binding

`execute-request` now derives a request-binding object from the verified signed
request and passes it to the collector. The aggregate report records:

- request ID;
- SHA-256 of the challenge nonce;
- target name;
- exact request JSON and request-signature hashes;
- signed request creation and expiry times;
- signed public-source identity;
- collection start and completion times.

The response signer requires an exact match between that binding and the
request being answered. Evidence without a binding, evidence from another
request, and evidence collected outside the signed request window are rejected
before a response is created.

## Verification

The detached verifier independently recomputes the expected binding from its
retained request and verifies the collection window, binding digest, response
statement, evidence manifest, operator signature, and execution-source
attestation. Exchange integrity remains separate from whether every external
product check passed.
