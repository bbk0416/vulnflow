# Signed external validation challenge-response exchange

## Problem

The 72.0.46 evidence verifier proves that one evidence directory is internally
consistent and bound to one public source manifest.  It does not prove who ran
the checks, whether the result answers a request retained by the reviewer, or
whether an attacker replaced the whole directory and recomputed its unsigned
manifest.

## Request challenge

The requester generates a short-lived Ed25519-signed request containing:

- a random 256-bit-equivalent challenge nonce;
- a unique request ID;
- target label;
- creation and expiration timestamps;
- exact application version, schema version, and public-manifest SHA-256;
- the complete required-check list for this release;
- scanner-corpus minimum and soak iteration parameters;
- requester key ID and pinned public-key fingerprint.

The runner must verify this request with a separately supplied requester public
key.  It refuses expired, modified, wrong-source, incomplete, or differently
scoped requests before executing validation.

## Signed response

After collecting evidence, the runner first invokes the independent v36
evidence verifier.  It then returns:

```text
request/
evidence/
operator-public-key.json
PAYLOAD_SHA256SUMS.txt
response-statement.json
response.ed25519
```

The response statement binds:

- the original request ID and challenge nonce;
- exact hashes of the request and its signature;
- request and response source identities;
- every request, evidence, and embedded public-key byte through a payload
  manifest;
- exact aggregate and evidence-manifest hashes;
- validation pass/completeness state and status counts;
- an operator label and pinned Ed25519 operator-key fingerprint.

The operator signature authenticates the response statement.  Private keys are
never copied into request or response bundles.

## Independent verification

The reviewer must retain the original request directory and separately pin both
public keys.  Verification requires all of the following:

1. embedded request equals the retained request byte-for-byte;
2. requester signature and request lifetime are valid;
3. request source identity matches the reviewing source tree unless detached
   verification is explicitly selected;
4. payload inventory has no extra, missing, linked, or modified files;
5. embedded operator identity equals the separately pinned operator key;
6. operator signature is valid;
7. evidence passes the independent v36 integrity verifier;
8. the response was created inside the signed request window;
9. response statement hashes and pass fields exactly match the evidence.

`integrity_passed=true` authenticates the exchange.  It does not imply
`validation_passed=true`.  A correctly signed result may still report Docker
unavailable, Chromium blocked, or customer scanner files not provided.

## Evidence semantic hardening

72.0.47 also closes an internal v36 verifier gap.  The verifier now enforces
which checks require JSON reports and which require child-execution records.  It
recomputes every check status from the child exit state and report contents,
rather than trusting aggregate status fields.  Removing a required report or
log, or changing a report from `passed` to `failed` while leaving the aggregate
unchanged, invalidates the evidence.

## Commands

Generate requester and operator key pairs separately:

```bash
python scripts/external_validation_exchange.py generate-key \
  --key-id requester-2026q3 \
  --private-output requester-private.json \
  --public-output requester-public.json

python scripts/external_validation_exchange.py generate-key \
  --key-id operator-2026q3 \
  --private-output operator-private.json \
  --public-output operator-public.json
```

Create and verify a request:

```bash
python scripts/external_validation_exchange.py create-request \
  --private-key-file requester-private.json \
  --operator-public-key-file operator-public.json \
  --output-dir validation-request \
  --target-name approved-lab

python scripts/external_validation_exchange.py verify-request validation-request \
  --requester-public-key-file requester-public.json
```

The signed request authorizes the exact operator key above. A substitute
operator key is rejected before the collector starts or output directories are
created. The external runner may execute the full collector and sign the
response in one command:

```bash
python scripts/external_validation_exchange.py execute-request \
  --request-dir validation-request \
  --requester-public-key-file requester-public.json \
  --operator-private-key-file operator-private.json \
  --evidence-output-dir external-evidence \
  --output-dir signed-response \
  --runner-label approved-lab-operator \
  --scanner-dir approved-anonymized-scanners
```

The reviewer verifies against the retained request and pinned keys:

```bash
python scripts/external_validation_exchange.py verify-response signed-response \
  --expected-request-dir validation-request \
  --requester-public-key-file requester-public.json \
  --operator-public-key-file operator-public.json
```

## Trust limit

This exchange proves possession of the pinned requester and operator keys and
binds a result to one challenge and one public source identity.  It does not
prove that the operator's host was uncompromised, that Docker or Chromium was
available, or that customer scanner files were representative.  Protect both
private keys outside the source and evidence directories and rotate them when
operator trust changes.
