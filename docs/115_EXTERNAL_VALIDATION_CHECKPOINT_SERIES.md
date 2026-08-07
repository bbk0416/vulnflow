# External-validation acceptance checkpoint series

VulnFlow 72.0.54 adds an append-only requester-signed series for acceptance-ledger checkpoints.

## Why a series is needed

A valid standalone checkpoint remains cryptographically valid forever. After a newer checkpoint is issued, an operator can accidentally select the older file and permit rollback to the older floor. Independent checkpoint files also do not show whether two same-generation checkpoints form competing branches.

## Series structure

The series directory contains requester metadata, the pinned requester public key, and sequential checkpoint envelopes. Each envelope binds:

- a contiguous generation;
- the previous checkpoint file SHA-256;
- requester identity and creation time;
- a strictly increasing ledger receipt count;
- ledger head receipt, request, and response identities.

A new checkpoint is published only when the current ledger extends the latest series head and contains at least one new receipt. Missing generations, unexpected files, signature changes, hash-chain changes, and requester substitution fail closed.

## CLI

```bash
python -m scripts.external_validation_acceptance append-checkpoint-series acceptance-ledger \
  --series-dir /independent-boundary/acceptance-checkpoints \
  --requester-private-key-file requester-private.json \
  --requester-public-key-file requester-public.json

python -m scripts.external_validation_acceptance verify-checkpoint-series \
  /independent-boundary/acceptance-checkpoints \
  --requester-public-key-file requester-public.json

python -m scripts.external_validation_acceptance verify-ledger acceptance-ledger \
  --requester-public-key-file requester-public.json \
  --minimum-checkpoint-series-dir /independent-boundary/acceptance-checkpoints
```

The entire series still has to be retained outside the acceptance-ledger rollback boundary. Rolling back the ledger and the complete external series together remains outside the protection of this local format.
