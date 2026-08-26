# VulnFlow 72.0.102 P0 scanner corpus closure evidence

This directory archives the compact post-release P0 scanner-corpus evidence for the official VulnFlow 72.0.102 Windows Core.

Official release identity:
- release: `v72.0.102`
- release commit: `c27634bbd28831896047440ff8d065256df827b2`
- Windows Core SHA-256: `96cfb8282f9fb60ffc0ec6c26b2625526370be89367b6fb32c9f96e7a98e4030`
- schema: `46`
- public regression contract: `727`

The post-release corpus gate contains four Nessus, four Greenbone XML, and four Greenbone CSV cases. Raw scanner exports are not copied into this repository. The closure manifest records the exact SHA-256 identities of the twelve external corpus objects and the generated review evidence.

Closure:
- technical corpus gate: `PASS`
- human semantic review: `12/12 PASS`
- machine semantic blockers: `0/12`
- Nessus single-label FQDN release regression: `CLOSED`
- Core defect proven: `False`
- release bump authorized: `False`

`GBCSV_001` contains two scanner observations that differ only by Greenbone Result ID. VulnFlow canonical automatic finding identity intentionally excludes scanner Result ID, so their convergence is source-duplicate provenance rather than a 72.0.102 Core defect.

This evidence does not certify every current or future Nessus or Greenbone export variant. It closes the P0 gate for the twelve exact corpus objects identified by SHA-256.
The four sealed evidence artifacts are stored with `-text` attributes so Git line-ending normalization cannot change their closure-time bytes.
