# Signed external validation runner kit

## Problem

72.0.47 authenticates the request and returned response, but a reviewer still
has to transfer the source tree, signed request, requester public key, and
execution instructions as separate objects.  That manual transfer can mix one
request with another source, omit files, alter launch wrappers, or introduce an
unsafe ZIP before the external operator runs validation.

## Runner kit

72.0.48 adds `scripts/external_validation_runner_kit.py`.  The requester builds
one deterministic ZIP containing:

```text
source/                       exact public-manifest source snapshot
request/                      signed request.json and request.ed25519
requester-public-key.json     convenience copy, not the trust anchor
RUN_EXTERNAL_VALIDATION.sh
RUN_EXTERNAL_VALIDATION.ps1
RUNNER_KIT_README.txt
KIT_SHA256SUMS.txt
runner-kit-statement.json
runner-kit.ed25519
```

The requester signature covers the payload-manifest SHA-256, exact request and
request-signature hashes, request ID, nonce, target, source identity, required
checks, parameters, and requester-key identity.  Recomputing the internal
manifest after changing a launcher or source file does not create a valid kit.

## Deterministic and safe archive contract

Identical source, request, and requester key inputs produce byte-identical ZIPs.
The archive uses one request-ID-derived root, normalized timestamps, normalized
regular-file modes, an exact payload inventory, and bounded entry and expanded
sizes.

Verification rejects:

- absolute, parent-traversal, backslash, duplicate, or multi-root ZIP paths;
- symbolic links and other special files;
- oversized entries or total expanded size;
- unexpected top-level files;
- missing, extra, or hash-mismatched payload files;
- a root name that does not match the signed request ID;
- a requester key different from the separately pinned public key;
- expired or wrong-source requests;
- source files that escape through a symbolic-link path component;
- a changed payload manifest whose hash no longer matches the signed statement.

## Commands

Build a kit with the requester key:

```bash
python scripts/external_validation_runner_kit.py create-kit \
  --request-dir validation-request \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json \
  --output-zip VulnFlow-validation-runner.zip
```

Verify the ZIP with a trusted verifier and an independently obtained requester
public key:

```bash
python scripts/external_validation_runner_kit.py verify-kit \
  VulnFlow-validation-runner.zip \
  --requester-public-key-file requester-public.json
```

Safely extract only after verification:

```bash
python scripts/external_validation_runner_kit.py extract-kit \
  VulnFlow-validation-runner.zip \
  --requester-public-key-file requester-public.json \
  --output-dir extracted-runner
```

From the extracted request-ID directory, run with the operator key stored
outside the kit:

```bash
./RUN_EXTERNAL_VALIDATION.sh \
  --requester-public-key-file /independent/requester-public.json \
  --operator-private-key-file /secure/operator-private.json \
  --evidence-output-dir /output/external-evidence \
  --output-dir /output/signed-response \
  --runner-label approved-lab-operator \
  --scanner-dir /approved/anonymized-scanners
```

The wrapper re-verifies the extracted kit before invoking the 72.0.47 signed
challenge-response collector.

## Trust limits

The embedded verifier, launcher, and public-key copy are convenience payloads.
The operator must verify the ZIP using a trusted verifier and a requester public
key obtained through an independent channel.  The kit does not contain either
private key, does not install a missing exact wheelhouse, does not provide
Docker or Chromium, and does not make absent customer scanner files pass.
