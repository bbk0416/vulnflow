# VulnFlow 72.0.37 release notes

VulnFlow 72.0.37 keeps SQLite schema 46 and adds authenticated integrity
sealing for retained offline deployments.

## Fixed defects

- Prevented a retained deployment whose code, identity marker, permissions, or
  filesystem layout changed after retention from remaining eligible for
  automatic rollback or pruning.
- Added a private deployment-history HMAC key beside the managed target and a
  mode-0600 authenticated seal for every newly retained deployment.
- Added deterministic whole-tree attestation covering regular-file content,
  relative paths, file and directory modes, owner/group IDs, symbolic-link targets, entry count,
  and total regular-file bytes.
- Made inventory, selection, rollback, and pruning fail closed when the history
  key is missing, the seal is invalid, or the retained tree no longer matches
  its sealed state.
- Added explicit legacy adoption rather than silently trusting v26 and older
  unsealed retained directories.

## Operator workflow

Newly retained deployments are sealed automatically. Existing unsealed history
is reported as unmanaged. After an operator independently reviews one legacy
retained tree, it can be adopted with an exact installation-ID confirmation:

```bash
python manage_offline_deployments.py adopt \
  --target /opt/vulnflow \
  --installation-id <32-hex-id> \
  --confirm ADOPT:<32-hex-id>
```

Adoption establishes trust in the current filesystem state. It does not prove
that the directory was historically untampered.

The private history key is stored beside the target as:

```text
.<target>.deployment-history.key
```

Loss of this key makes sealed history unverifiable. It must be included in the
operator's protected configuration backup, but never committed or copied into a
public release artifact.

## Verification scope

The public core contract expands from 440 to 447 tests. New tests cover code and
identity tampering, missing and wrong history keys, prune preservation of
suspect trees, explicit legacy adoption, refusal to overwrite an invalid seal,
and authenticated sealing of the deployment displaced by rollback.

The seal protects against accidental modification and unprivileged changes to a
retained directory. It does not defend against a privileged actor that can both
modify the deployment tree and read or replace the history key, and it does not
attest external executables referenced by symbolic links.
