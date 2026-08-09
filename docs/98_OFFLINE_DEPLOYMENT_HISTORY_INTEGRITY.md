# Offline deployment history integrity

VulnFlow 72.0.37 keeps SQLite schema 46 and authenticates the retained
filesystem trees used by offline rollback and retention management.

## Why the identity marker was insufficient

The 72.0.36 identity marker recorded the installation ID, version, schema,
release-kit digest, and release-key fingerprint. Those fields identified a
retained deployment but did not cryptographically bind the marker to the files
that would later be executed.

A local modification to application code or the identity marker could therefore
remain eligible for list, rollback, and prune as long as the JSON remained
syntactically valid.

## History key and seal

The first retained deployment creates a random 32-byte mode-0600 key beside the
managed target:

```text
.<target>.deployment-history.key
```

Each validated previous deployment receives:

```text
config/OFFLINE_DEPLOYMENT_SEAL.json
```

The seal contains no credentials. It binds:

- installation ID and target name;
- SHA-256 of the canonical identity marker;
- deterministic whole-tree SHA-256;
- regular-file byte count and total entry count;
- history-key fingerprint;
- UTC sealing time;
- HMAC-SHA-256 authentication tag.

The tree digest includes relative paths, entry type, permission mode, owner/group IDs, regular
file size and content digest, and symbolic-link target. The seal file itself is
excluded from the digest.

## Fail-closed management

The following operations verify the history key, seal, identity, and a freshly
computed tree digest before acting:

- retained-deployment inventory;
- rollback candidate selection;
- automatic retention pruning;
- explicit rollback.

A missing key, modified code, modified identity, invalid seal, unsafe
permissions, or unsupported filesystem entry moves the path to `unmanaged`.
Automatic pruning never deletes such a path.

## Legacy adoption

Retained trees created before 72.0.37 have no seal and are not trusted
automatically. After independent review, an operator may establish a new local
baseline:

```bash
python manage_offline_deployments.py adopt \
  --target /opt/vulnflow \
  --installation-id <32-hex-id> \
  --confirm ADOPT:<32-hex-id>
```

Adoption refuses to overwrite any existing seal, including an invalid one. This
prevents an integrity failure from being silently converted into a new trusted
baseline.

## Backup requirement

The history key is outside the active deployment directory so activating or
rolling back a tree cannot replace it. Operators must back it up with the same
care as other local recovery secrets. Losing the key does not delete deployment
history, but automatic verification and rollback remain unavailable until the
original key is restored.

## Limits

- A privileged actor with access to both the retained tree and history key can
  forge a new valid seal.
- Symbolic-link target strings are authenticated, but the contents of external
  targets are not copied into the tree digest.
- The seal authenticates a retained filesystem snapshot; it is not a remote
  attestation, hardware root of trust, or substitute for signed release-kit
  verification and external backups.
- Legacy adoption authenticates the reviewed current state only and cannot
  prove historical integrity.
