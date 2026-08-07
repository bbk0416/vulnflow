# Offline recovery-journal key lifecycle

VulnFlow 72.0.43 adds explicit lifecycle management for the symmetric key that authenticates interrupted deployment-history recovery journals.

> **Superseded for restore operations:** VulnFlow 72.0.44 requires witness-signed v2 backups and additional CLI arguments. See [105_WITNESSED_RECOVERY_JOURNAL_KEY_BACKUP.md](105_WITNESSED_RECOVERY_JOURNAL_KEY_BACKUP.md).

## Why lifecycle management is required

The 72.0.42 journal key was created automatically and protected as a local `0600` trust anchor, but there was no supported way to inspect, back up, restore, or rotate it.

If the key was lost while an authenticated journal remained pending, signed startup preflight correctly blocked service startup but the operator had no safe way to prove that a candidate key belonged to that journal. Manually replacing the file could silently install an unrelated or older key.

## Commands

Inspect the current key and its binding to pending journals:

```bash
python manage_offline_deployments.py journal-key-status \
  --target /opt/vulnflow
```

Create a target-bound private backup:

```bash
python manage_offline_deployments.py backup-journal-key \
  --target /opt/vulnflow \
  --output /secure-offline/vulnflow-journal-key.json \
  --confirm BACKUP-RECOVERY-JOURNAL-KEY
```

Restore a missing key:

```bash
python manage_offline_deployments.py restore-journal-key \
  --target /opt/vulnflow \
  --source /secure-offline/vulnflow-journal-key.json \
  --confirm RESTORE-RECOVERY-JOURNAL-KEY
```

Rotate the key when no recovery transaction is pending:

```bash
python manage_offline_deployments.py rotate-journal-key \
  --target /opt/vulnflow \
  --confirm ROTATE-RECOVERY-JOURNAL-KEY
```

## Restore boundary

A candidate backup is parsed and validated before any live file changes. When a journal is pending, the candidate key must validate all of the following for every transaction:

```text
journal-key fingerprint
canonical manifest HMAC
transaction target and state
previous keyring size and SHA-256
previous audit-log size and SHA-256
```

Only then is the key installed. A wrong key or damaged backup inventory is rejected before the current key path is changed.

When no journal is pending, an existing different key cannot be replaced from backup. The operator must use explicit rotation instead. This prevents a stale backup from silently rolling the journal trust anchor backwards.

## Rotation boundary

Rotation is rejected while any recovery transaction directory exists. With no pending transaction, VulnFlow:

```text
reads and validates the current key
→ writes a new random 32-byte key atomically
→ records old and new fingerprints in the authenticated deployment audit
→ restores the old key if audit append fails
```

## Backup boundary

The backup is target-name bound, mode `0600`, single-file JSON containing the raw secret key in hexadecimal form and its SHA-256 fingerprint. It is not encrypted by VulnFlow. Store it only on encrypted offline media with restricted operator access.

If the audit event for backup creation cannot be committed, the newly written backup is removed rather than leaving an unaudited secret copy.

## Limitations

This lifecycle remains a host-side symmetric-key boundary. A privileged actor who can read and rewrite the live key, backup, journal, and deployment audit can forge a consistent state. The backup does not replace the externally witnessed keyring-and-audit recovery bundle, and rotation does not provide historical verification for journals signed by a discarded key. Therefore rotation is allowed only when no journal is pending.
