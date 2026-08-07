# External-validation acceptance ledger minimum checkpoint

VulnFlow 72.0.53 adds a requester-signed minimum checkpoint for the external-validation acceptance ledger.

## Previous boundary

The 72.0.52 ledger signed every receipt and chained each receipt to the previous receipt SHA-256. That detects tampering, replay, and operator equivocation while the complete ledger is retained. A valid historical prefix is still internally consistent, however. An attacker who replaces the whole ledger with an older signed prefix can make later accepted requests disappear without breaking any receipt signature.

## Minimum checkpoint

`create-checkpoint` verifies the complete ledger and creates a requester-signed envelope containing:

- requester key identity;
- receipt and accepted-request counts;
- current head receipt SHA-256;
- head request ID and response-tree SHA-256;
- checkpoint creation time.

The checkpoint must be stored outside the ledger rollback boundary. It is published exclusively and never contains requester private-key material.

## Guarded verification and acceptance

`verify-ledger --minimum-checkpoint-file` requires the current ledger to contain the exact checkpointed receipt at the checkpoint sequence. It rejects:

- a ledger shorter than the checkpoint;
- a different valid branch at or before the checkpoint;
- a modified or differently signed checkpoint;
- a checkpoint signed by another requester key.

`accept-response --minimum-checkpoint-file` applies the same check before publishing a new receipt. A rolled-back ledger therefore cannot silently reaccept a removed request or accept a conflicting response while the trusted checkpoint is supplied.

A valid ledger may extend beyond the checkpoint. Operators should issue and independently retain a newer checkpoint after important acceptances. A checkpoint stored on the same storage snapshot as the ledger can be rolled back with it and does not provide an independent monotonic floor.

## CLI

```bash
python -m scripts.external_validation_acceptance create-checkpoint \
  acceptance-ledger \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json \
  --output-file /independent-boundary/acceptance-minimum.json

python -m scripts.external_validation_acceptance verify-checkpoint \
  /independent-boundary/acceptance-minimum.json \
  --requester-public-key-file requester-public.json

python -m scripts.external_validation_acceptance verify-ledger \
  acceptance-ledger \
  --requester-public-key-file requester-public.json \
  --minimum-checkpoint-file /independent-boundary/acceptance-minimum.json

python -m scripts.external_validation_acceptance accept-response \
  --response-dir response \
  --expected-request-dir request \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json \
  --operator-public-key-file operator-public.json \
  --ledger-dir acceptance-ledger \
  --minimum-checkpoint-file /independent-boundary/acceptance-minimum.json
```
