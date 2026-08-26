# CVE-less findings and scanner-source observations

## Decision

CVE becomes optional for scanner/import findings without creating a second
observation model. The existing `findings` -> `source_finding_records` ->
`finding_observations` chain is reused.

`cve_id` remains `TEXT NOT NULL`; missing CVE is represented by the empty
string, so no physical SQLite schema change is required. Malformed non-empty
CVE values remain invalid. CVE-only intelligence, VEX, and OSV workflows remain
strict.

CVE-bearing rows keep the historical canonical-key algorithm exactly. CVE-less
rows derive a semantic surrogate from product/component/version and stable
service/port notes, then delegate to that historical algorithm. Scanner Result
IDs are deliberately excluded from canonical identity.

`source_finding_id` is an optional provenance field. Nessus uses host + plugin
ID + endpoint + CVE/NO-CVE. Greenbone/OpenVAS preserves Result ID when
available, otherwise OID/name + host/port, with CVE/NO-CVE suffixing for
multi-CVE source items.

Distinct scanner Result IDs may therefore remain distinct source records while
converging to one canonical finding.

SQLite schema stays at 46. The immutable `v72.0.102` tag and release asset are
not modified. This lands on `main` as unreleased Core work.
