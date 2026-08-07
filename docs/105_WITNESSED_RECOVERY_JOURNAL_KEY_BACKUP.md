# Witness-signed recovery-journal key backup

VulnFlow 72.0.44 replaces the self-consistent v1 journal-key backup with a generation-aware v2 document signed by an externally protected Ed25519 witness key.

## Threat addressed

The 72.0.43 backup stored the raw 32-byte HMAC key and a SHA-256 fingerprint. An attacker could generate a different key, recompute its fingerprint, and produce a structurally valid backup. When the live key was missing and no recovery journal was pending, the file had no independent authenticity anchor.

The v2 backup signs the following canonical fields together:

```text
backup ID and timestamp
deployment target name
raw secret key and SHA-256 fingerprint
monotonic journal-key generation
authenticated audit sequence and head
witness key ID and pinned public-key fingerprint
```

Changing any field invalidates the Ed25519 signature.

## Create a signed backup

Generate and externally protect a witness key pair using the existing witness command, then create the backup:

```bash
python manage_offline_deployments.py backup-journal-key \
  --target /opt/vulnflow \
  --output /secure-offline/vulnflow-journal-key-v2.json \
  --witness-private-key /secure-offline/history-witness-private.json \
  --confirm BACKUP-RECOVERY-JOURNAL-KEY
```

The witness private key must remain outside the deployment host whenever possible. The backup still contains the raw symmetric journal key and therefore belongs on encrypted offline media.

## Restore with an external generation floor

```bash
python manage_offline_deployments.py restore-journal-key \
  --target /opt/vulnflow \
  --source /secure-offline/vulnflow-journal-key-v2.json \
  --trusted-witness-public-key /etc/vulnflow/history-witness-public.json \
  --minimum-witness-receipt /secure-external/latest-history-witness.json \
  --confirm RESTORE-RECOVERY-JOURNAL-KEY
```

Before changing the live key, restore verifies:

1. the backup signature against the pinned public key;
2. target, key length, fingerprint, generation, and audit checkpoint;
3. the backup checkpoint against authenticated deployment history;
4. the external minimum witness receipt and its audit prefix;
5. that the backup generation is not below the witness-derived generation;
6. that it is not below the current authenticated audit generation;
7. that its fingerprint matches that generation;
8. every pending v3 recovery journal and its previous-file inventory.

When live history files are damaged during an interrupted recovery, the generation policy is evaluated against the authenticated previous keyring and audit snapshot preserved inside the journal, without installing either file first.

## Compatibility

Unsigned `vulnflow-offline-deployment-recovery-journal-key-backup/1` files are rejected. Create a new v2 backup while the 72.0.44 live key is available. Retain the earlier backup only as emergency evidence; it is not an accepted automated restore input.

## Security boundary

This design detects backup forgery and rollback as long as the trusted public key and minimum witness receipt are protected outside the local rollback boundary. It does not defend against compromise of the witness private key, nor does it encrypt the raw journal key contained in the backup.
