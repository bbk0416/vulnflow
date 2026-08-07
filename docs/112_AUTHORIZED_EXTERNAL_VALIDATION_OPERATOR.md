# Authorized external-validation operator

VulnFlow 72.0.51 binds each signed external-validation challenge to one
explicitly authorized operator Ed25519 key.

## Previous boundary

The requester signed the exact source identity, target, nonce, validity window,
required checks, and execution parameters. The response verifier pinned an
operator public key separately, but the challenge itself did not identify the
operator allowed to answer it. A substituted operator could create another
validly signed response, and a verifier using the substituted public key had no
challenge-contained authorization record with which to reject it.

## Request authorization

`create-request` now requires `--operator-public-key-file`. Request format v2
records and signs:

- signature algorithm;
- authorized operator key ID;
- authorized operator public-key fingerprint.

Only public identity is included. No private-key material is copied into the
request or runner kit.

## Enforcement

Before response output is created, `sign-response` and `execute-request` load
the operator private key and require its derived public-key identity to match
the signed request. `run-directory` performs the same check before launching a
child process.

The detached response verifier independently requires equality between:

- the signed request authorization;
- the response statement authorization;
- the embedded operator public key;
- the separately pinned operator public key;
- the key that verifies the response signature.

A changed authorization invalidates the requester signature. A different
operator key is rejected even if it can produce a cryptographically valid
Ed25519 signature of its own.
