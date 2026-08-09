# Offline deployment external witness

VulnFlow 72.0.39 adds an external Ed25519 witness receipt for the offline
deployment-history audit chain.

The local keyring checkpoint added in 72.0.39 detects deletion or truncation of
only the audit file. It cannot distinguish a legitimate older snapshot from an
attacker restoring the keyring and audit file together to the same earlier
point. Both local files remain internally consistent after that coordinated
rollback.

A witness receipt signs one audit sequence and entry hash with a private key
kept outside the deployment host. The corresponding public key and the latest
receipt must be pinned on an independent system. Verification accepts a local
log that contains the witnessed prefix and may contain newer events. It rejects
a local log that is shorter than the receipt or has a different entry hash at
the witnessed sequence.

## Generate an offline witness key

Create the key pair in a private directory. The private key file is mode 0600
and must not be copied to the deployment host for routine verification.

```bash
python manage_offline_deployments.py generate-witness-key \
  --private-key /secure-offline/vulnflow-witness-private.json \
  --public-key /etc/vulnflow/vulnflow-witness-public.json \
  --key-id operations-witness-1 \
  --confirm GENERATE-HISTORY-WITNESS
```

Keep the private key on encrypted offline media or a separately administered
signing system. Pin the public key independently of the deployment directory.

## Issue a checkpoint receipt

Stop or otherwise serialize offline deployment administration, then issue a
receipt after a successful deployment, rollback, prune, key rotation, or audit
verification.

```bash
python manage_offline_deployments.py issue-witness \
  --target /opt/vulnflow \
  --private-key /secure-offline/vulnflow-witness-private.json \
  --output /external-witness/vulnflow-checkpoint-20260803T210000Z.json \
  --confirm ISSUE-HISTORY-WITNESS
```

The receipt contains no HMAC secret. It contains the deployment target name,
audit sequence and head hash, current local history-key identifier and
fingerprint, witness key identifier, issue time, and an Ed25519 signature.
Store receipts on an append-only, WORM, versioned object store, or another host
outside the deployment administrator's write boundary.

## Verify local history against the witness

```bash
python manage_offline_deployments.py verify-witness \
  --target /opt/vulnflow \
  --public-key /trusted-config/vulnflow-witness-public.json \
  --receipt /external-witness/vulnflow-checkpoint-20260803T210000Z.json
```

A successful result reports the witnessed sequence, the current local
sequence, and how many local events were added after the receipt.

Verification fails when:

- the receipt signature or trusted public key does not match;
- the receipt was issued for a different target name;
- the local audit log is shorter than the witnessed sequence;
- the entry hash at the witnessed sequence differs;
- the local keyring or audit chain cannot be verified.

## Trust and recovery limits

The receipt is useful only when the latest trusted receipt and public key are
kept outside the same rollback boundary as the local keyring and audit log. An
attacker who can replace the local state, the trusted public key, and the
external receipt with a coordinated older set can still hide rollback.

This release does not yet create a single atomic disaster-recovery bundle that
contains the keyring and audit log. The existing keyring backup protects only
the secret keyring; the audit log still requires an independently protected
backup. Do not restore either file in isolation without first validating the
complete retained-deployment seals, audit chain, and latest external witness.

The witness is not a public transparency service, trusted timestamp, HSM, TPM,
or remote-attestation system. It provides an operator-controlled external
checkpoint for a single-host offline deployment workflow.
