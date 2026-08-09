# Authenticated offline recovery journal

VulnFlow 72.0.42 authenticates interrupted deployment-history recovery journals before the signed offline launcher restores any live history file.

## Why the v2 inventory was insufficient

The 72.0.41 journal recorded the size and SHA-256 of the previous keyring and audit log. That detected accidental corruption, but an actor able to rewrite the journal directory could replace a backup and update the unkeyed digest in `transaction.json`.

The v3 journal binds the complete transaction manifest with HMAC-SHA-256.

```text
transaction state
transaction ID and creation time
target deployment name
previous-file presence flags
previous-file sizes and SHA-256 values
journal-key fingerprint
→ canonical JSON
→ HMAC-SHA-256
```

A changed state, target, inventory row, or backup digest fails before any backup is copied into the live keyring or audit path.

## Trust anchor

The journal key is stored beside the deployment target rather than inside the transaction directory.

```text
.<target>.deployment-history.journal-auth.key
```

Boundary:

- exactly 32 random bytes;
- mode `0600` on POSIX;
- one regular file with one hard link;
- deployment-account ownership;
- created with `O_EXCL` so concurrent first use has one winner;
- never included in Git, release ZIPs, runtime reports, or recovery journals.

The separate key remains stable while the history keyring itself is being replaced or rolled back.

## Startup behavior

```text
acquire deployment operation lock
→ discover matching transaction directories
→ require exactly one v3 authenticated journal
→ read protected journal key
→ verify key fingerprint and manifest HMAC
→ verify backup size and SHA-256 inventory
→ restore previous keyring and audit pair
→ verify audit chain and retained deployment seals
→ remove journal only after verification
→ start application
```

Startup is blocked when:

- the journal HMAC is invalid;
- the journal key is missing, replaced, linked, foreign-owned, or too permissive;
- the manifest target or state was rewritten;
- a backup file or its inventory changed;
- more than one journal exists;
- the journal uses the unauthenticated v1 or v2 format.

## Legacy recovery

The v2 journal from 72.0.40–72.0.41 contains a file-integrity inventory but no authentication. It is not recovered automatically.

```bash
python manage_offline_deployments.py recover-interrupted \
  --target /opt/vulnflow \
  --allow-legacy \
  --confirm RECOVER-LEGACY-HISTORY-JOURNAL
```

This confirmation means the operator has independently reviewed the journal directory and accepts the unkeyed inventory as the recovery basis.

## Limitations

The HMAC key is local and symmetric. A privileged actor able to read the key can forge a valid journal. A storage administrator can also roll back the key and journal together. External rollback resistance still depends on the Ed25519 witness and witnessed history-recovery bundle. The journal key must be included in protected host-configuration backup, but it must not be stored inside the same pending transaction directory it authenticates.
