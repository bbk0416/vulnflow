# External-validation checkpoint-series transfer

VulnFlow 72.0.55 adds a deterministic requester-signed transfer bundle for copying an acceptance checkpoint series to an independent storage boundary.

## Why direct file copies are insufficient

Every checkpoint is individually signed, so an interrupted copy that contains only an older prefix is still internally valid. A normal series verifier cannot know that a newer source head existed. Manual directory replacement can also overwrite a newer destination with an older or forked series.

## Signed transfer bundle

`build-transfer` verifies the complete source series and signs an exact transfer statement containing:

- requester key identity;
- checkpoint count and head checkpoint SHA-256;
- head generation, receipt count, and receipt SHA-256;
- every transferred file path, size, and SHA-256;
- a canonical series-tree SHA-256.

The ZIP uses deterministic metadata and one bounded root. Verification rejects duplicate or unsafe paths, symbolic and special files, oversized expansion, truncated archives, signature changes, and inventory mismatch. Requester private-key material is never included.

## Monotonic resumable installation

`install-transfer` first verifies the entire archive in a private temporary directory. It then compares the incoming chain with the installed destination:

- an older incoming head is rejected;
- an equal head is an idempotent no-op;
- an incoming fork is rejected;
- a valid extension publishes only missing immutable checkpoint files in generation order.

If installation stops after one generation, the destination remains a valid prefix and the same transfer can safely resume. Existing checkpoint files are never replaced.

## CLI

```bash
python -m scripts.external_validation_checkpoint_transfer build-transfer \
  /independent-boundary/acceptance-checkpoints \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json \
  --output-zip acceptance-checkpoints-transfer.zip

python -m scripts.external_validation_checkpoint_transfer verify-transfer \
  acceptance-checkpoints-transfer.zip \
  --requester-public-key-file requester-public.json

python -m scripts.external_validation_checkpoint_transfer install-transfer \
  acceptance-checkpoints-transfer.zip \
  --series-dir /remote-independent-boundary/acceptance-checkpoints \
  --requester-public-key-file requester-public.json
```

A previously signed older bundle can initialize an empty destination if an operator deliberately selects it. To prevent that operational mistake, retain the expected transfer SHA-256 or expected head checkpoint SHA-256 outside the transport channel. Once a destination has a newer valid head, monotonic installation prevents rollback to the older bundle.
