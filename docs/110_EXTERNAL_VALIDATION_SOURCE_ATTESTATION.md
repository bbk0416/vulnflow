# External validation source attestation and execution snapshot

## Problem

The signed request binds the SHA-256 of `SHA256SUMS.txt`. That identifies the
intended public source manifest, but hashing only the manifest file is not the
same as proving that every listed file still has the expected bytes at the
moment validation runs.

In 72.0.48 the runner kit was verified before launch. A listed Python file could
still be modified after that verification and before the child process read it,
or `execute-request` could be invoked directly from a modified tree while the
manifest file stayed unchanged.

## Full public-source attestation

72.0.49 adds `scripts/external_validation_source_attestation.py`. It:

1. parses `SHA256SUMS.txt` with duplicate and unsafe-path rejection;
2. resolves every listed path inside the source root;
3. rejects symbolic-link components and non-regular files;
4. hashes every listed file and compares it with the manifest;
5. records the version, schema, manifest entry count, manifest SHA-256, and a
   canonical verified-tree SHA-256.

A signed request is accepted only after this complete verification succeeds.

## Private execution snapshot

The collector no longer runs directly from the extracted kit tree. The runner:

1. verifies the signed kit;
2. copies only public-manifest files into a new private temporary directory;
3. verifies the copied snapshot;
4. launches `external_validation_exchange.py` from that snapshot;
5. creates another manifest-only snapshot for the collector itself;
6. verifies the execution snapshot again after collection;
7. signs both matching source identities into the response.

Unlisted files are deliberately not copied. A planted `sitecustomize.py`, local
scratch script, database, cache, or unrelated workspace artifact therefore
cannot enter the execution snapshot merely by existing beside the source.

## Response contract

Response format v2 includes:

```json
{
  "source_attestation": {
    "format": "vulnflow-external-validation-source-attestation/1",
    "mode": "execute-request-pre-post",
    "before": {"...": "verified identity"},
    "after": {"...": "same verified identity"}
  }
}
```

The verifier independently rechecks the retained source and requires the signed
before/after identities to be equal. A detached, post-hoc signing operation is
identified as `detached-signing-current-source`; its exchange integrity may be
valid, but it is not promoted to a complete passed execution.

## Limits

This is a filesystem and process-launch integrity boundary, not a trusted
execution environment. Root, kernel, hypervisor, interpreter, dependency, or
operator-key compromise remains outside the claim.
