# Offline deployment startup recovery preflight

VulnFlow 72.0.41 makes interrupted deployment-history recovery a startup boundary for signed offline installations.

## Why this exists

A history recovery restores two files as one logical state:

- the deployment-history HMAC keyring;
- the authenticated deployment audit log.

A process interruption between those replacements can leave a private journal beside the deployment target. Earlier releases recovered it only when the recovery CLI was run again, so an operator could start the service while deployment-history files were inconsistent.

## Startup behavior

The signed offline launcher runs the reviewed preflight module before importing the web application.

```text
acquire deployment operation lock
→ inspect matching recovery journals
→ no journal: continue startup
→ one v2 journal: validate inventory and restore previous pair
→ verify audit chain and retained deployment seals
→ remove journal only after verification
→ start application
```

Startup is blocked when:

- more than one journal exists;
- a matching path is a symlink, file, or unsafe directory;
- journal permissions or ownership are unsafe;
- the journal backup size or SHA-256 differs from its manifest;
- the restored audit history or retained seal does not verify;
- the journal is the legacy v30 format without a file-integrity inventory.

## Operator commands

Inspect without modification:

```bash
python manage_offline_deployments.py interrupted-recovery-status \
  --target /opt/vulnflow
```

Recover one current journal manually:

```bash
python manage_offline_deployments.py recover-interrupted \
  --target /opt/vulnflow
```

A legacy v30 journal requires explicit review and confirmation:

```bash
python manage_offline_deployments.py recover-interrupted \
  --target /opt/vulnflow \
  --allow-legacy \
  --confirm RECOVER-LEGACY-HISTORY-JOURNAL
```

## Trust boundary

The v2 journal records sizes and SHA-256 digests to detect corruption and incomplete writes. Its protection still depends on a private parent directory, mode-0700 journal directory, mode-0600 files, and the operating-system account boundary. An attacker able to read and rewrite all journal files can also rewrite the unkeyed inventory. External rollback resistance remains the role of the Ed25519 witness and witnessed recovery bundle.
