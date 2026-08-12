# VulnFlow 72.0.78

72.0.78 is a narrow IDNA canonicalization and scanner-source normalization integrity patch on the feature-frozen 72.0.72 line.

## Fixed

- Canonicalize FQDN identity with the already-pinned `idna` package using non-transitional IDNA2008/UTS #46 processing instead of applying Unicode `casefold()` before the built-in codec. This prevents distinct domains such as `faß.de` / `fass.de` and Greek sigma / final-sigma labels from being merged into one asset.
- Normalize scanner-source labels to Unicode NFC before case folding so canonically equivalent composed/decomposed labels share the same source-record, snapshot-absence, and canonical `source_count` boundary.
- Preserve stable Unicode U-label / ASCII A-label compatibility lookups for identifiers written by earlier releases, so existing valid IDN assets continue to reconcile after upgrade.
- Reject repeated trailing root dots while continuing to accept a single conventional trailing root dot.

## Compatibility boundary

- Existing ambiguous assets that were already merged by pre-72.0.78 lossy IDNA normalization are not automatically split; the patch prevents new false merges and preserves legacy lookup compatibility.
- Existing 72.0.77 Unicode FQDN identifier rows remain resolvable through U-label compatibility matching without a schema rewrite.
- Scanner connectors, CSV/XLSX parsing, preview/apply behavior, and authoritative scanner asset-ID separation are unchanged.

## Unchanged

- SQLite schema remains 46.
- Dependency package pins are unchanged.
- The feature-frozen remediation closeout product scope is unchanged.
