# Offline deployment key lifecycle and audit chain

VulnFlow 72.0.38 keeps SQLite schema 46 and extends retained-deployment history
from one static HMAC key to a versioned local keyring with authenticated
operation history.

## Files beside the deployment target

For a target such as `/opt/vulnflow`, the management boundary uses:

```text
/opt/.vulnflow.deployment-history.key
/opt/.vulnflow.deployment-history.audit.jsonl
/opt/.vulnflow.previous-*/config/OFFLINE_DEPLOYMENT_SEAL.json
```

The keyring and audit log must be regular, single-link, mode-0600 files. They
must not be committed, placed inside a release ZIP, or copied to unencrypted
shared storage.

## Key rotation

```bash
python manage_offline_deployments.py rotate-key \
  --target /opt/vulnflow \
  --confirm ROTATE-HISTORY-KEY
```

Rotation:

1. verifies the current inventory and audit chain;
2. upgrades the legacy single-key format when necessary;
3. creates a new current key and marks the old key retired;
4. reseals every managed retained deployment with the new current key;
5. records a chained `history_key_rotated` event;
6. restores the previous keyring, seals, and audit log if any step fails.

Retired keys remain in the keyring only so pre-rotation audit events can be
verified. Retained-deployment seals are accepted only when authenticated by the
current key, so restoring an old seal after rotation is fail-closed.

The keyring has a bounded key count. Key removal is intentionally not automated
because deleting a retired key would make older audit events unverifiable.

## Keyring backup and restore

Create a private backup only on encrypted offline media:

```bash
python manage_offline_deployments.py backup-key \
  --target /opt/vulnflow \
  --output /secure-offline/vulnflow-history-keyring.backup \
  --confirm BACKUP-HISTORY-KEYRING
```

The backup contains raw secret HMAC material. It is mode 0600 but is not
passphrase-encrypted by VulnFlow.

Restore after key loss:

```bash
python manage_offline_deployments.py restore-key \
  --target /opt/vulnflow \
  --source /secure-offline/vulnflow-history-keyring.backup \
  --confirm RESTORE-HISTORY-KEYRING
```

Before accepting a backup, restore verifies every existing sealed retained tree
and the full external audit chain. An incompatible or stale backup is rejected,
and the pre-restore keyring and audit log are restored automatically.

## External authenticated audit chain

The append-only JSONL chain records deployment activation, adoption, rollback,
prune, key backup, key restore, and key rotation events. Each record contains a
sequence number, previous-entry SHA-256, key ID, key fingerprint, operation
metadata, and HMAC-SHA-256. The keyring stores the latest committed sequence and
entry hash, so deleting the audit file or truncating it to an otherwise valid
prefix is fail-closed.

```bash
python manage_offline_deployments.py verify-audit \
  --target /opt/vulnflow
```

Audit append uses an exclusive file lock and re-verifies the existing chain
inside the same critical section. This prevents two direct callers from
creating the same sequence number.

## Limitations

- The keyring backup is confidential secret material but is not encrypted by
  the application.
- A privileged attacker who can modify the keyring, audit log, and retained
  trees together is outside this local-file HMAC threat model.
- Loss of retired keys prevents verification of audit events signed by those
  keys.
- The JSONL audit chain is local evidence, not remote timestamping or hardware
  attestation.
- Rotation does not prove that history was uncompromised before the rotation.
