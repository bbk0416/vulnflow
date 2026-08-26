# P0 real/public scanner corpus closure

VulnFlow 72.0.102 completed a post-release P0 real/public scanner-corpus recheck against the exact official Windows Core.

## Release identity

- version: `72.0.102`
- release commit: `c27634bbd28831896047440ff8d065256df827b2`
- official Windows Core SHA-256: `96cfb8282f9fb60ffc0ec6c26b2625526370be89367b6fb32c9f96e7a98e4030`
- schema: `46`
- public regression contract: `727`

The released `v72.0.102` tag and release asset are not modified by this evidence publication.

## Corpus result

- corpus slots: `12/12`
- public-corpus technical gate: `PASS`
- human semantic review: `12/12 PASS`
- machine semantic blockers: `0/12`
- `NESSUS_002` single-label FQDN release regression: `CLOSED`
- Core defect proven: `False`
- release bump authorized: `False`
- P0 real/public corpus gate: `PASS`

## Exact corpus identities

| Case | SHA-256 | Human verdict |
| --- | --- | --- |
| NESSUS_001 | `d16684ed2e16e35ee302c16fc09ba6d2060e0a678136f195dd745b66dc3626b9` | PASS |
| NESSUS_002 | `6d268a41a0f605dcbcb266abfe18572a415ddfb0c7faf09db1551343c4d51254` | PASS |
| NESSUS_003 | `5a4288335972a543c71ee618148c2df4d6699a2e83801648c9f247415acf2291` | PASS |
| NESSUS_004 | `ffe0306a4ec2b33b4a0c39031fe556aa0425f1359fd7f0fef24700eb79de6928` | PASS |
| GBXML_001 | `9b5a65e0d92cc7d853084d129ea6260ab34b46136fb05ec6aa2f80db4830356e` | PASS |
| GBXML_002 | `fbfcf5cc8c3e031ca4139241f4006bd79f9d9ee0f2c2d31e4744c0ebe8135339` | PASS |
| GBXML_003 | `bb88fdad0451bab6374591884816dcc81630739b18d674d9a71122a2ea47ec9b` | PASS |
| GBXML_004 | `f78cbc429c0f156bd8cd1678288835de76a71ce3bf37184da88cc80fc8522bb5` | PASS |
| GBCSV_001 | `808e198ae15e12b27dfc8a730b9ad0294ecfb23d2bf9511171d0e8beaa3b219d` | PASS, source duplicate reviewed |
| GBCSV_002 | `ff92d3f4b7f019bb4f3b335ff437e7cc268bada99fd487801c70949c8a5036eb` | PASS |
| GBCSV_003 | `4ff858e7a9d2bfe3d60cb8a95cec357936711ae2e87ccc82a0ecd349edf0d29a` | PASS |
| GBCSV_004 | `ba081714418b334b9feb8d2426e076f9ff01c60de02fa66ea191679a625d3026` | PASS |

## Semantic interpretation

Nessus multi-CVE plugins whose representative CVSS value cannot be safely assigned to one CVE keep per-CVE CVSS blank rather than inventing attribution. CVE identity and endpoint values remain preserved.

CVE-less Nessus/OpenVAS observations excluded by the current model are explicit exclusions rather than parser failures. This is a current product-model limitation.

`GBCSV_001` initially produced eleven duplicate automatic finding-ID preview errors. FIX2 proved that two source records differed only in scanner Result ID and carried the same eleven CVEs. Canonical finding identity intentionally excludes scanner Result ID, so the failure was reclassified as `VALIDATION_TOOLING_DEFECT_SOURCE_DUPLICATE`, not a Core defect.

## Evidence integrity

- packet TXT SHA-256: `bbc2917ad8a12e6389b47a6d2829afd70f3446b9c5e32216a7eed71db59934fd`
- packet JSON SHA-256: `daaacfac931f194c5b2e568a6658c2396e02c0173878563b3d267f47fb7d65f7`
- human closure SHA-256: `85bad0a65e4858c4939955614962963e501720797b625e231dcb5fb7f113397c`
- final closure manifest SHA-256: `9830428470e3554aa4f978971858bd6eff664805dbbcefc73488eb50e83e192b`

The four archived closure artifacts use repository-local `-text` attributes so Git line-ending normalization does not alter their sealed SHA-256 bytes.

## Limits

This closure applies to the twelve exact corpus objects above. Public historical samples and parser-test fixtures validate those file shapes; they do not certify current vendor behavior across every Nessus or Greenbone version.

Within this bounded P0 contract, no additional VulnFlow 72.0.102 Core defect was proven and a 72.0.103 release bump is not authorized by this corpus gate.
