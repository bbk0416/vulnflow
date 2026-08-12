# VulnFlow 72.0.80

72.0.80 is a narrow asset-identity and reconciliation-state integrity patch on the feature-frozen 72.0.72 line.

## Fixed

- Normalize generic asset identifiers such as scanner/external IDs and HOSTNAME values to Unicode NFC before case folding. Canonically equivalent NFC/NFD spellings now share one identifier rather than producing a different asset identity.
- Normalize HOSTNAME environment scope and fallback asset identity inputs to the same NFC + casefold boundary, preventing equivalent Unicode environment/name values from splitting one asset.
- Apply active source-conflict decisions only while the chosen source record is PRESENT. An authoritative source that becomes ABSENT no longer leaves its stale value overriding currently observed sources.
- Do not treat an ABSENT chosen source as resolving a conflict among remaining PRESENT sources.
- Preserve the operator decision itself while the source is absent so it becomes effective again if that source later returns PRESENT.

## Compatibility boundary

- Existing ASCII asset identifier normalization is unchanged.
- Existing source-conflict decisions are not deleted or rewritten; their effective application now follows the chosen source record's PRESENT/ABSENT state.
- Pre-72.0.80 databases that already contain duplicate assets created only by Unicode canonical-equivalence differences are not automatically merged. The patch prevents new splits and rejects no valid equivalent reimport after upgrade.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- Scanner connectors and supported scanner file formats are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
