# Requester acceptance ledger for external validation

VulnFlow 72.0.52 adds an explicit requester-side acceptance step after detached
external-validation response verification.

## Previous boundary

A response could be independently authentic, source-attested, bound to the exact
challenge, and signed by the authorized operator.  The verifier was still
stateless: verifying the same response twice produced the same successful
result, and two different operator-signed responses for one request could each
pass independent verification.

That behavior is correct for signature verification but unsafe for automated
approval and audit workflows.  A verifier needs durable requester-side state to
distinguish first acceptance from replay and conflicting second responses.

## Acceptance receipt

`accept-response` first runs the full response verifier, then creates one
requester-signed receipt containing:

- request ID, target, request and request-signature hashes;
- exact response-tree SHA-256 and file count;
- response statement, response signature, and embedded operator-key hashes;
- requester and operator identities;
- response integrity, source-attestation, completion, and validation results;
- sequence number and previous-receipt SHA-256.

The receipt is published as one complete JSON envelope only after its signature
has been created.  The ledger directory stores the requester public key,
metadata, and sequential receipt envelopes.  It never stores requester private
key material.

## Replay and equivocation handling

For a request ID already present in the ledger:

- the same response-tree hash is rejected as a replay;
- a different response-tree hash is rejected as operator equivocation.

A new receipt is not created in either case.  Concurrent writers compete for the
same sequence filename; only one can publish it and the other must retry after
revalidating the ledger.

## Verification

`verify-ledger` checks exact directory inventory, the embedded and independently
pinned requester public key, contiguous sequence numbers, the receipt hash
chain, every Ed25519 signature, unique request IDs, and response-tree hash
syntax.

The ledger detects replay and conflicting responses as long as the requester
retains its ledger state.  It is not a hardware-backed monotonic counter and
does not by itself prove that an attacker with full control of all requester
storage has not rolled the entire ledger back.  The returned head receipt hash
should be retained in an independent audit or backup boundary when rollback
resistance is required.

## CLI

```bash
python -m scripts.external_validation_acceptance accept-response \
  --response-dir response \
  --expected-request-dir request \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json \
  --operator-public-key-file operator-public.json \
  --ledger-dir acceptance-ledger

python -m scripts.external_validation_acceptance verify-ledger \
  acceptance-ledger \
  --requester-public-key-file requester-public.json
```
