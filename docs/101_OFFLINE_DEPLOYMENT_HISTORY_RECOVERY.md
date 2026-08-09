# Offline deployment history recovery bundle

VulnFlow 72.0.40 treats the deployment-history keyring and authenticated audit
log as one recovery unit. A key-only backup remains useful as emergency secret
material, but it cannot establish a consistent point-in-time audit recovery by
itself.

## Create a bundle

Issue or select an externally stored witness receipt first, then run:

```bash
python manage_offline_deployments.py create-recovery-bundle \
  --target /opt/vulnflow \
  --public-key /trusted-config/vulnflow-witness-public.json \
  --witness-receipt /external-witness/vulnflow-checkpoint.json \
  --output /secure-offline/vulnflow-history-recovery.zip \
  --confirm CREATE-HISTORY-RECOVERY-BUNDLE
```

The output is mode `0600` and contains:

- `history-keyring.bin` — secret current/retired HMAC keyring;
- `history-audit.jsonl` — the matching authenticated audit chain;
- `witness-receipt.json` — the signed checkpoint used when creating the bundle;
- `witness-public-key.json` — an evidence copy of the pinned public key;
- `manifest.json` and `SHA256SUMS.txt` — target, checkpoint, file size, and
  per-member digest contracts.

The public-key copy inside the ZIP is not trusted by itself. Verification always
requires an independently supplied trusted public-key file and compares it byte
for byte with the bundled copy.

## Verify without restoring

```bash
python manage_offline_deployments.py verify-recovery-bundle \
  --target /opt/vulnflow \
  --bundle /secure-offline/vulnflow-history-recovery.zip \
  --public-key /trusted-config/vulnflow-witness-public.json \
  --minimum-witness /external-witness/latest-approved-checkpoint.json
```

Verification checks ZIP boundaries, checksums, manifest consistency, the full
HMAC audit chain, the keyring checkpoint, both witness receipts, and every
currently managed retained-deployment seal. A bundle older than the external
minimum witness fails.

## Restore

Stop VulnFlow before restore:

```bash
python manage_offline_deployments.py restore-recovery-bundle \
  --target /opt/vulnflow \
  --bundle /secure-offline/vulnflow-history-recovery.zip \
  --public-key /trusted-config/vulnflow-witness-public.json \
  --minimum-witness /external-witness/latest-approved-checkpoint.json \
  --confirm RESTORE-HISTORY-RECOVERY-BUNDLE
```

The candidate pair is verified in a private sibling directory before either
live file is replaced. If the current local audit is valid and newer than the
bundle, restore is refused. During replacement VulnFlow records the prior pair
in a mode-`0700` rollback transaction directory. Failure restores both prior
files; an interrupted transaction is recovered on the next restore attempt.
After successful installation VulnFlow appends a
`history_recovery_bundle_restored` event and re-verifies the external minimum
witness.

## Boundaries

- The ZIP contains unencrypted HMAC secrets. Use encrypted offline storage.
- The trusted public key and minimum witness must remain outside the deployment
  host's rollback boundary.
- The service must be stopped; the CLI serializes deployment mutations but does
  not make a running process reload two files atomically.
- A bundle does not restore retained deployment directories themselves. Any
  retained directories still present must verify under the recovered keyring.
- A root or storage administrator who can replace the bundle, public key,
  witness, and deployment filesystem together remains outside this local trust
  model.
