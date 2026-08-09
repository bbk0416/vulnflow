# Offline deployment history, rollback, and retention

VulnFlow 72.0.36 keeps SQLite schema 46 and adds a managed lifecycle for the
private sibling trees retained by the signed offline deployment bootstrap.

## Problems addressed

Before this release, every successful `--force` replacement retained another
`.<target>.previous-*` directory indefinitely. The deployment report exposed
only the newest path; there was no supported inventory, verified rollback, or
bounded pruning command. Concurrent bootstrap processes could also mutate the
same target at the same time.

The v25 release kit had another standalone boundary defect: it signed and
shipped `offline_deployment_bootstrap.py`, but that file imported a separate
activation module that was not included as a release-kit artifact. Source-tree
rehearsals therefore passed while the documented isolated bootstrap command
could fail at import time.

## Deployment identity

Every new offline deployment contains a mode-0600 marker:

```text
config/OFFLINE_DEPLOYMENT_IDENTITY.json
```

It records only non-secret deployment metadata:

- random installation ID;
- application and schema version;
- pinned release-kit SHA-256;
- pinned release public-key fingerprint;
- UTC installation time;
- managed target name.

Automatic inventory and pruning manage only real, private directories carrying
a valid marker for the expected target. Legacy, damaged, symlinked, or otherwise
unmanaged paths are reported and left untouched.

## Operator commands

Stop VulnFlow before rollback or prune.

```bash
python manage_offline_deployments.py list \
  --target /opt/vulnflow

python manage_offline_deployments.py rollback \
  --target /opt/vulnflow \
  --installation-id <32-hex-id> \
  --confirm ROLLBACK:<32-hex-id>

python manage_offline_deployments.py prune \
  --target /opt/vulnflow \
  --keep 3 \
  --dry-run

python manage_offline_deployments.py prune \
  --target /opt/vulnflow \
  --keep 3 \
  --confirm PRUNE
```

A rollback uses the same same-filesystem atomic activation and post-rename
service/SQLite verification as a replacement. The deployment that was active
before rollback becomes another retained candidate, allowing a forward return.
If rollback verification fails, both the current deployment and the rollback
candidate are restored to their original paths.

Rollback reactivates a previously retained fresh deployment tree. It is not an
in-place schema downgrade or production-data migration.

## Retention

The bootstrap accepts:

```text
--retain-previous 3
```

The default retains the three newest managed previous deployments. At least one
managed previous deployment must be preserved. Unmanaged paths are never
deleted automatically.

Retention runs only after activation checks and the initial deployment report
have committed. A pruning or report-update failure does not roll back a valid
new deployment after older trees may already have been removed.

## Concurrency boundary

Bootstrap, rollback, and prune share a private POSIX advisory lock beside the
target. The kernel releases the lock if a process crashes, so a stale lock file
does not block future work. Symlinked or non-regular lock files are rejected.

This serializes VulnFlow's supported offline deployment tools. It does not stop
an unrelated privileged process from modifying the same filesystem.

## Signed release-kit contract

The release distribution now requires four signed deployment artifacts:

- `offline_deployment_activation.py`;
- `offline_deployment_history.py`;
- `offline_deployment_bootstrap.py`;
- `manage_offline_deployments.py`.

Regression coverage copies only these four files into an isolated directory and
executes both command-line entry files there, preventing accidental dependency
on the source repository.

## Limits

- Existing v25 and older retained trees do not have the identity marker and are
  reported as unmanaged until reviewed manually.
- The retained tree contains its own data and credentials; capacity planning and
  an external backup policy remain necessary.
- Rollback verification proves bounded startup, authentication, persistence,
  SQLite integrity, and expected schema. It is not a cryptographic re-attestation
  of every installed file after local administrators may have modified it.
- Windows offline runtime installation remains outside the current signed-kit
  contract.
