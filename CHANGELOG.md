> Historical per-iteration release notes from 72.0.11 through 72.0.94 are preserved under `docs/archive/releases/`. The current release note remains at `RELEASE_NOTES_72.0.95.md`.

## Unreleased — Free Public Beta productization (documentation/config only)

- Position the existing 72.0.72 core as `VulnFlow Free — Public Beta` without changing application behavior, schema, dependencies, or version.
- Define a non-retroactive path from the current MIT release to a possible future subscription edition after commercial readiness.
- Replace portfolio-only support wording with best-effort Free Beta support boundaries.
- Add scanner-compatibility and beta-feedback issue templates with explicit sensitive-data safeguards.
- Keep feature development evidence-driven during the free validation phase.



## 72.0.95 — 2026-08-20

- Bind Greenbone GMP XML EPSS tuples to the representative nested `cve@id` instead of copying one NVT-level `max_severity` score onto every expanded CVE row.
- Preserve both representative contracts: `max_severity` for the highest-severity CVE and `max_epss` for the highest-EPSS CVE, leaving unrelated referenced CVEs without scanner-supplied EPSS.
- Add one end-to-end two-CVE attribution regression covering XML parse, canonical mapping, normalization, batch import, and persisted per-CVE EPSS values; public collection contract is 720 tests (78 + 76 + 168 + 80 + 117 + 67 + 134), with platform-specific skips reported explicitly.
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.94 — 2026-08-19

- Preserve current Greenbone GMP XML `nvt/epss/max_severity/score` and `percentile` values through scanner-specific canonical import instead of silently dropping them.
- Follow the GMP `max_severity` EPSS semantics explicitly; do not substitute the separate `max_epss` aggregate.
- Add one end-to-end regression covering XML parse, canonical mapping, normalization, batch import, and persisted EPSS score/percentile; public collection contract is 719 tests (78 + 76 + 168 + 80 + 117 + 67 + 133), with platform-specific skips reported explicitly.
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.93 — 2026-08-19

- Preserve current Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT detailed CSV `EPSS score` and `EPSS percentile` values through scanner-specific canonical import instead of silently dropping them.
- Expose `epss_percentile` in the canonical import mapping contract so the scanner adapter can carry both official EPSS fields into the existing schema 46 finding fields.
- Add one end-to-end regression covering current detailed CSV parse, canonical mapping, normalization, batch import, and persisted EPSS score/percentile; public collection contract is 718 tests (78 + 76 + 168 + 80 + 117 + 67 + 132), with platform-specific skips reported explicitly.
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.92 — 2026-08-19

- Support current Greenbone OPENVAS SECURITY INTELLIGENCE/OPENVAS REPORT detailed CSV exports that use `CVE references` together with `Vulnerability name`, host identity fields, and optional `Port/Protocol`.
- Route the current Greenbone header profile through the OpenVAS CSV adapter so CVE identity and endpoint-specific canonical components are preserved instead of falling back to generic CSV handling with a missing `cve_id`.
- Add one end-to-end current-export regression covering auto-detection, `CVE references`, vulnerability naming, distinct `443/tcp` versus `8443/tcp` component identity, and successful two-row batch import; public collection contract is 717 tests (78 + 76 + 168 + 80 + 117 + 67 + 131), with platform-specific skips reported explicitly.
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.91 — 2026-08-18

- Support Greenbone/OpenVAS Customizable CSV exports that separate endpoint data into `Port` and `Port Protocol`, preserving `443/tcp` versus `443/udp` canonical identity.
- Recognize the current `VT Name` header for OpenVAS CSV auto-detection and product/component naming while retaining legacy `NVT Name` aliases.
- Add one end-to-end customizable CSV regression covering auto-detection, VT naming, protocol-preserving component identity, and successful two-row batch import; public bounded suite is 716 tests (78 + 76 + 168 + 80 + 117 + 67 + 130).
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.90 — 2026-08-18

- Recognize the modern Greenbone/OpenVAS CSV `Port/Protocol` header as the endpoint source instead of only accepting the legacy `Port` header.
- Preserve concrete multi-port endpoint identity for modern CSV exports so same NVT/CVE findings on `443/tcp` and `8443/tcp` do not collapse into one canonical key and reject the batch.
- Add one end-to-end modern CSV header regression; public bounded suite is 715 tests (78 + 76 + 168 + 80 + 117 + 67 + 129).
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.89 — 2026-08-17

- Preserve concrete Greenbone/OpenVAS numeric port endpoints in canonical component identity for both CSV and XML imports.
- Keep host-level `0/tcp`, `general/tcp`, and empty port values backward-compatible.
- Add one end-to-end XML+CSV multi-port import regression; public bounded suite is 714 tests (78 + 76 + 168 + 80 + 117 + 67 + 128).
- SQLite schema remains 46 and dependency package pins are unchanged.

## 72.0.88 — 2026-08-15

- Preserve the Nessus ReportItem port/protocol endpoint in canonical component identity so the same plugin/CVE on different ports remains distinct.
- Keep host-level `port=0` plugin component identity unchanged while allowing valid multi-port `.nessus` exports to import instead of failing as duplicate canonical findings.
- Add one end-to-end multi-port import regression; public bounded suite is 713 tests (78 + 76 + 168 + 80 + 117 + 67 + 127).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.87 — 2026-08-14

- Reject SMBIOS all-zero and all-FF `bios-uuid` sentinel values from Tenable `.nessus` authoritative scanner asset identity.
- Preserve `host-uuid` priority, valid BIOS UUIDs, and McAfee ePO GUID fallback while preventing unrelated hosts with an absent BIOS UUID from false-merging into one VulnFlow asset.
- Add an end-to-end parser/identity false-merge regression; public bounded suite is 712 tests (78 + 76 + 168 + 80 + 117 + 67 + 126).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.86 — 2026-08-14

- Preserve Greenbone/OpenVAS result-host `<asset asset_id="...">` UUIDs as canonical scanner asset IDs instead of discarding the vendor's stable asset identity.
- Keep one Greenbone asset/finding continuous across IP/FQDN changes when the scanner asset UUID is unchanged, preventing identity splits caused only by network renaming or address churn.
- Add an end-to-end parser/identity regression; public bounded suite is 711 tests (78 + 76 + 168 + 80 + 117 + 67 + 125).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.85 — 2026-08-13

- Exclude Greenbone/OpenVAS nested delta-history `<result>` elements from current finding imports instead of treating comparison history as independent active findings.
- Preserve ordinary report XML and direct `get_results_response` result imports while stopping descent at the first importable result boundary.
- Add a delta-report regression; public bounded suite is 710 tests (78 + 76 + 168 + 80 + 117 + 67 + 124).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.84 — 2026-08-13

- Honor Tenable `.nessus` `has_patch` as the authoritative structured patch-availability signal when present, preventing generic solution guidance from overriding `has_patch=false`.
- Preserve explicit `has_patch=true`, fail closed on malformed non-boolean values with a parser warning, and retain the legacy solution-text fallback only when `has_patch` is absent.
- Add 3 Nessus semantic regressions; public bounded suite is 709 tests (78 + 76 + 168 + 80 + 117 + 67 + 123).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.

## 72.0.83 — 2026-08-13

- Fix Greenbone/OpenVAS remediation semantics so an explicit `Solution Type` reports a patch only for `VendorFix`; `Workaround`, `Mitigation`, `NoneAvailable`, and `WillNotFix` no longer masquerade as patch availability.
- Preserve the legacy solution-text fallback for exports that omit `Solution Type`.
- Add XML/CSV regressions for the corrected mapping; public bounded suite is 706 tests (78 + 76 + 168 + 80 + 117 + 67 + 120).
- Keep SQLite schema 46, dependency package pins, supported scanner connector set, and the feature-frozen product scope unchanged.

## 72.0.82 — 2026-08-13

- Correct stale public regression counts, first-admin/control DB paths, and login rate-limit documentation.
- Add a fail-closed documentation/runtime-contract consistency gate to public CI and submission readiness.
- Add 5 documentation-contract regressions; public bounded suite is 704 tests (78 + 76 + 168 + 80 + 117 + 67 + 118).
- Keep SQLite schema 46, dependency package pins, scanner connectors, and feature scope unchanged.

## 72.0.81 — 2026-08-12

- Refresh canonical product/component versions when currently PRESENT sources converge on one non-empty value, fixing sticky single-source reimports without arbitrarily collapsing unresolved multi-source conflicts.
- Treat a stored reconciliation decision as effective only while the chosen PRESENT source currently supplies that field; preserve the decision while inactive and reactivate it automatically if the field returns.
- Reuse scanner-derived assets during inventory enrichment through normalized external identity so inventory linking does not create a competing authoritative asset or break later scanner reimports.
- Normalize inventory external IDs and batch duplicate detection to Unicode NFC + casefold, rejecting canonically equivalent duplicate authoritative identifiers before partial writes.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.

## 72.0.80 — 2026-08-12

- Normalize non-FQDN asset identifiers, HOSTNAME environment scope, and fallback asset identity inputs to Unicode NFC before case folding so canonically equivalent scanner spellings do not split or reject one asset.
- Ignore an active source-reconciliation decision while its chosen source record is ABSENT, preventing stale authoritative values from overriding currently PRESENT scanner observations or falsely resolving remaining conflicts.
- Re-enable the same reconciliation decision automatically when the chosen source becomes PRESENT again, preserving operator intent without applying stale observations during absence.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.

## 72.0.79 — 2026-08-12

- Normalize canonical component/product identity text to Unicode NFC before case folding so canonically equivalent scanner spellings do not split one vulnerability into duplicate canonical findings.
- Normalize all fields used to derive AUTO finding IDs to NFC before case folding, stabilizing generated source IDs across composed/decomposed Unicode spellings while preserving existing ASCII-generated IDs.
- Align preview and apply duplicate finding-ID checks with the source-record identity contract (NFC + casefold), so case/Unicode-equivalent source-native IDs fail during preview instead of passing preview and failing apply.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.

## 72.0.78 — 2026-08-12

- Canonicalize FQDN identity with the pinned `idna` implementation using non-transitional IDNA2008/UTS #46 processing, preventing distinct domains such as `faß.de`/`fass.de` and sigma/final-sigma labels from being merged.
- Normalize scanner-source keys to Unicode NFC before case folding so composed/decomposed spellings share snapshot absence and logical source-count boundaries.
- Preserve legacy Unicode U-label lookup compatibility for valid IDNs written by earlier releases without a schema rewrite.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.

## 72.0.77 — 2026-08-12

- Use Unicode `casefold()` rather than SQLite ASCII-only `LOWER()` for snapshot scanner-source equivalence, preventing non-ASCII case-only source labels from escaping missing-source reconciliation.
- Count case-fold-equivalent scanner-source labels as one logical source in canonical aggregation even when multiple native source records remain present.
- Match stable IDNA Unicode and punycode FQDN spellings during asset identity resolution without rewriting stored identifiers or overriding authoritative scanner asset IDs.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.76 — 2026-08-12

- Prevent supported CSV/XLSX duplicate-header suffix collisions from silently overwriting a column value when a generated name such as `notes_2` is already present.
- Reject malformed explicit FQDN asset identifiers at the central identity boundary instead of accepting invalid hostnames into reconciliation.
- Make scanner-source reconciliation stable across case-only source-name changes by reusing the case-folded source-record identity and applying the same equivalence during missing-source snapshot handling.
- Keep SQLite schema 46, dependency package pins, scanner connectors, and the feature-frozen product scope unchanged.


## 72.0.75 — 2026-08-11

- Validate explicit FQDN/IP/MAC finding identifiers during import preview so rows that would fail reconciliation are reported before apply instead of failing the whole batch later.
- Accept bracketed IPv6 literals consistently in the central asset-identity normalizer and prevent bracketed IPv6 scanner targets from being recorded as false HOSTNAME aliases.
- Preserve physical source-row provenance for multiline CSV records and XLSX files whose header begins after leading blank rows, including overflow error locations.
- Keep UTF-16 generic CSV outside the documented encoding contract; supported generic CSV encodings remain UTF-8 variants plus CP949/EUC-KR fallback.
- Keep SQLite schema 46, dependency package pins, and the feature-frozen product scope unchanged.


## 72.0.74 — 2026-08-11

- Replace permissive scanner host/IP regex classification with exact `ipaddress` validation.
- Prevent hostnames such as `db01`, `cafe`, `face01`, and `dead.beef` from being written into `ip_address` and subsequently failing asset-identity reconciliation.
- Normalize valid IPv4/IPv6 scanner host values and downgrade malformed explicit Nessus `host-ip` values to parser warnings.
- Raise the GitHub public-CI per-group guard from 300 to 360 seconds after a verified transient Windows runner timeout; timeouts remain fail-closed.
- Keep schema 46, dependency package pins, and the feature-frozen product scope unchanged.


## 72.0.73 — 2026-08-10

- Reject CSV records with non-empty fields beyond the declared header width instead of silently truncating them.
- Parse CSV in strict mode so malformed or unterminated quoted fields fail closed rather than absorbing later rows.
- Bound XLSX header width at the final non-empty header cell and reject non-empty data beyond that boundary.
- Keep schema 46, dependency locks and the feature-frozen product scope unchanged.


## 72.0.72 — 2026-08-07

- Freeze new feature development for the pilot candidate and shift the default product surface toward remediation work instead of validation machinery.
- Make scanner data a required pilot-launch condition so an empty configured project cannot be labelled launch-ready.
- Replace the raw verification timeline with a localized actionable review queue, status counters, evidence counts, and direct pending-work navigation.
- Correct the public quick-start to use the locked launchers and align README test counts and product-status claims with the 663-test public core.
- Keep SQLite schema 46 and the existing vulnerability-management domain model unchanged.

## 72.0.71 — 2026-08-07

- Clone FastAPI parameter defaults from their constructor-time metadata instead of reusing alias and annotation state mutated by template-route analysis.
- Serialize complete application router assembly, including shared request-scoped router inclusion, to prevent concurrent Pydantic schema mutation.
- Promote `UnsupportedFieldAttributeWarning` to an error in the concurrent two-application contract and add a 12-round standalone warning gate.
- Keep SQLite schema 46, 276 effective routes, request-scoped pilot behavior, and all product HTTP contracts unchanged.

## 72.0.70 — 2026-08-07

- Register request-scoped DI routers through the public `FastAPI.include_router()` API instead of the lower-level application router implementation.
- Restore the four pilot routes on Windows FastAPI 0.140.9, preserving the full 276-route table.
- Narrow direct-transfer restrictions to the 15 legacy cloned routers and add an explicit public-registration regression contract.
- Preserve SQLite schema 46 and all endpoint behavior.

## 72.0.68 — 2026-08-07

- Migrated the four pilot routes from mutable module globals to request-scoped FastAPI `ApplicationContext` dependency resolution.
- Registered the pilot router normally across applications while retaining the in-memory cloning compatibility path for the other 15 router modules.
- Added concurrent two-application isolation coverage and mixed shared/cloned runtime ownership contracts.
- Preserved 276 routes and SQLite schema 46.

## 72.0.67 — 2026-08-06

- Removed runtime router source reads and `compile/exec` re-execution.
- Added in-memory function namespace and APIRoute metadata cloning for isolated applications.
- Preserved 276 routes, application-specific dependency globals, restart behavior, and lifecycle cleanup.
- Added regression contracts proving router source files are not opened, compiled, or executed during cloning.

## 72.0.66 — 2026-08-06

- Make ordinary Windows and Linux launchers install the exact `requirements.lock` runtime closure through the virtual-environment interpreter.
- Remove implicit unpinned pip upgrades and duplicate Windows batch installation logic.
- Enforce the packaged dependency manifest by default and add optional explicit wheelhouse installation.
- Add local-launcher dependency-lock regression coverage and static consistency checks.

## 72.0.65 — 2026-08-06

- Release isolated endpoint functions retained by FastAPI callable-classification LRU caches after application shutdown.
- Add feature-detected cleanup for generator, async-generator, and coroutine callable caches while preserving the primary process runtime.
- Add four v123 regressions and expand the public core contract from 643 to 647 tests; group 3 expands from 148 to 152.
- Keep SQLite schema 46 and the 24 MiB Python-allocation bound unchanged.

## 72.0.64 — 2026-08-06

- Replace Windows-sensitive global `APIRoute` count equality with direct weak-reference reclamation checks for every application, route, and endpoint created by the repeated isolated-app regressions.
- Preserve the 72.0.63 router-transfer product code, schema 46, 276-route application table, and 24 MiB allocation bound unchanged.
- Record the independent Windows 72.0.63 result as five passed external checks, one unavailable Docker engine, one not-provided customer corpus, and no product failure.
- Keep the public core contract at 643 tests while removing a false negative caused by delayed collection of objects created by earlier tests.

## 72.0.63 — 2026-08-06

- Bypass FastAPI `include_router()` for isolated applications and transfer 276 private `APIRoute` objects directly into the owning application.
- Restore Windows FastAPI 0.140.9 route availability after 72.0.62 incorrectly cleared the retained source router and produced 404 health responses.
- Rebind each transferred route to the application dependency provider, refresh its request handler, and preserve restart and garbage-collection contracts.
- Add four v122 regressions and expand the public core contract from 639 to 643 tests while keeping SQLite schema 46 and the 24 MiB allocation bound unchanged.

## 72.0.62 — 2026-08-06

- Release private source `APIRouter.routes` immediately after `include_router()` copies all 276 routes into an isolated application.
- Break the remaining Windows CPython 3.13 cycle that retained exactly one source route set, 16 namespaces, endpoint globals, and Pydantic/FastAPI metadata per completed lifecycle.
- Add four v121 regressions for source-route release, restart safety, repeated route/namespace collection, and primary-router preservation; expand the public core contract from 635 to 639 tests.
- Keep SQLite schema 46, application route behavior, browser workflows, and the 24 MiB Python-allocation bound unchanged.

## 72.0.61 — 2026-08-06

- Replace synthetic isolated router `ModuleType` objects with private `SimpleNamespace` globals while preserving per-application dependency isolation and restart behavior.
- Prevent CPython 3.13 on Windows from retaining 16 synthetic router modules per completed application lifecycle through framework schema caches.
- Add four v120 regressions for namespace type, module-registry exclusion, restart rebinding, and repeated garbage collection; expand the public core contract from 631 to 635 tests.
- Remove inherited `FORCE_COLOR` from bounded public-test subprocesses so JSON-emitting administration CLIs remain machine-readable.
- Keep SQLite schema 46 and product behavior unchanged; preserve the 24 MiB Python-allocation bound.

## 72.0.60 — 2026-08-05

- Break isolated router-module references back to completed FastAPI application lifespans while preserving process-level compatibility routers.
- Rebind the mutable dependency overrides and the owning application on restart so a released isolated application can safely enter a later lifespan.
- Add four v119 regressions for shutdown release, restart safety, garbage collection, and primary-runtime preservation; expand the public core contract from 627 to 631 tests.
- Keep SQLite schema 46 and product behavior unchanged.

## 72.0.59 — 2026-08-05

- Classify a present Docker CLI with an unreachable Docker Desktop engine as `unavailable` during collection while keeping `--require-docker` fail-closed.
- Bind the finding-detail browser workflow to the rendered breadcrumb and H1 identity instead of stale copy that was never present in the page.
- Start `tracemalloc` before warm-up lifecycles and hide warm-up samples, preserving the 24 MiB steady-state bound without untracked-allocation distortion on Windows.
- Add four v118 regressions and expand the public core contract from 623 to 627 tests while keeping SQLite schema 46 unchanged.

## 72.0.58 — 2026-08-05

- Fix direct execution of the production Compose rehearsal by bootstrapping the repository import root before importing shared TLS helpers.
- Scope browser E2E success notices to visible notice elements and expand the approval-history disclosure before asserting approved request visibility.
- Measure Python allocation growth only after explicit steady-state warm-up cycles while preserving the 24 MiB bound and recording actual/limit evidence.
- Add v117 regression coverage for direct-script imports, warm-up-aware bounded allocation checks, continued leak rejection, and browser locator contracts.

## 72.0.57 — 2026-08-05

- Fixed the final Windows public-regression failure by comparing generated database paths as path components instead of hard-coded POSIX separator strings.
- Added an explicit regression for both Windows and POSIX path forms and expanded the public core contract from 618 to 619 collected tests.
- Kept SQLite schema 46 and all application runtime behavior unchanged.

## 72.0.56 — 2026-08-05

- Fixed Windows SQLite backup publication by applying the durability fsync through a writable descriptor, eliminating the shared `EBADF` failure across backup, background-job, and soak workflows.
- Replaced external OpenSSL CLI use in SMTP and production Compose rehearsals with `cryptography`, used cross-platform Compose bind syntax, and guaranteed a structured failure report.
- Declared the signed offline deployment v95-v104 runtime POSIX-only, corrected Windows path and browser harness defects, added the missing `idna==3.17` closure pin, and added eight v116 regression tests.
- Expanded the public core contract from 610 to 618 collected tests while keeping SQLite schema 46 unchanged.

## 72.0.55 — 2026-08-04

- Added deterministic requester-signed transfer bundles for acceptance checkpoint series, binding the exact series inventory and head identity.
- Added resumable monotonic installation that only appends missing immutable generations and rejects stale or forked bundles.
- Added seven v115 regression tests and expanded the public core contract from 603 to 610 tests while keeping SQLite schema 46 unchanged.

## 72.0.54 — 2026-08-04

- Added an append-only requester-signed acceptance checkpoint series with contiguous generations and previous-checkpoint SHA-256 chaining.
- Ledger verification and response acceptance can use the series head directly, preventing stale individual checkpoint selection and refusing checkpoint advancement from a rolled-back or divergent ledger.
- Added six v114 regression tests and expanded the public core contract from 597 to 603 tests while keeping SQLite schema 46 unchanged.

# Changelog

## 72.0.54 — 2026-08-04

- Added requester-signed minimum checkpoints for the external-validation acceptance ledger.
- Rejected a valid but older ledger prefix, a divergent branch, and new receipt publication when the independently retained checkpoint is not satisfied.
- Added six v113 regression tests and expanded the public core contract from 591 to 597 tests while keeping SQLite schema 46 unchanged.

## 72.0.52 — 2026-08-04

- Added a requester-signed, hash-chained acceptance ledger for verified external-validation responses.
- Rejected repeated presentation of the same accepted response as replay and a different second response for the same request as operator equivocation.
- Added six v112 regression tests and expanded the public core contract from 585 to 591 tests while keeping SQLite schema 46 unchanged.

## 72.0.51 — 2026-08-04

- Bound each signed external-validation challenge to one authorized operator Ed25519 key ID and public-key fingerprint.
- Rejected operator-key substitution before response output creation and before runner-kit child execution.
- Added six v111 regression tests and expanded the public core contract from 579 to 585 tests while keeping SQLite schema 46 unchanged.

This public changelog summarizes the portfolio-facing release line. It does not reproduce every internal verification iteration.

## 72.0.50 — 2026-08-04

- Bound external-validation evidence collection to the exact signed request ID, nonce digest, request bytes, signature bytes, target, source identity, and request validity window.
- Rejected unbound, cross-request, stale, future, and post-response evidence before operator response signing.
- Added six v110 regression tests and expanded the public core contract from 573 to 579 tests while keeping SQLite schema 46 unchanged.

## 72.0.49 — 2026-08-04

- Added full public-source attestation that hashes every manifest-listed file instead of trusting only the manifest file digest.
- Executes external validation from private manifest-only snapshots and excludes unlisted source injection from the execution tree.
- Added signed pre/post execution source identities and response format v2; detached post-hoc signing cannot promote a result to passed validation.
- Added bounded external-command process groups and direct-to-log capture so a successful wrapper cannot hang evidence collection through a descendant-held stdout pipe.
- Made the completed standalone runtime soak terminate deterministically after its reports are durable, preventing a clean 12-cycle PASS from lingering in interpreter shutdown.
- Added seven v109 regression tests and expanded the public core contract from 566 to 573 tests while keeping SQLite schema 46 unchanged.

## 72.0.48 — 2026-08-04

- Added a deterministic requester-signed external-validation runner kit that combines the exact public source snapshot, signed request, requester public-key copy, and launch wrappers.
- Added direct ZIP verification and safe extraction with one request-ID-derived root, exact payload inventory, normalized metadata, bounded expansion, and special-file rejection.
- Required an independently pinned requester public key and rejected changed launchers even when an attacker recomputes the unsigned payload manifest.
- Added fourteen v108 regression tests and expanded the public core contract from 552 to 566 tests while keeping SQLite schema 46 unchanged.

## 72.0.47 — 2026-08-04

- Added an Ed25519-signed external validation challenge-response exchange bound to a retained request, exact public source manifest, and separately pinned runner key.
- Kept exchange integrity separate from product validation so signed blocked, unavailable, or missing checks remain non-passing.
- Hardened detached evidence verification to require each check's expected JSON report and execution record and to recompute status from those bytes.
- Added request expiry, nonce, source identity, private-key permission, path-overlap, payload inventory, and replay/wrong-key attack tests.

## 72.0.46 — 2026-08-04

- Bound every mandatory child JSON report to both a zero subprocess exit and the exact report SHA-256, preventing stale, missing, malformed, contradictory, or post-success-crash reports from becoming passes.
- Added an independent evidence-directory verifier for recursive inventory hashes, execution-log and report digests, aggregate contracts, source version, schema, and public-manifest identity.
- Required a collector-owned path marker before destructive evidence-directory overwrite and rejected output-directory or evidence-file symbolic links.
- Read customer scanner exports once for both parsing and hashing, rejected symbolic links and bounded corpus file/byte counts, and sanitized parser failures so filenames and exception text are not copied into evidence.
- Added fourteen focused regression tests and expanded the public core contract from 525 to 539 tests while keeping SQLite schema 46 unchanged.

## 72.0.45 — 2026-08-04

- Added an external validation evidence gate that keeps pass, fail, blocked, unavailable, missing-corpus, insufficient-corpus, and manual-review outcomes distinct.
- Added managed Chromium all-URL policy detection and machine-readable browser evidence without converting an environment block into a product pass.
- Added privacy-preserving customer scanner corpus evidence using opaque IDs, suffixes, sizes, SHA-256 hashes, and parser outcomes while excluding source contents and filenames.
- Required at least 20 unique scanner file contents by default and rejected duplicate copies as corpus inflation.
- Added a SHA-256 evidence manifest and strict release mode that fails unless all seven external validation contracts pass.
- Added ten regression tests and expanded the public core contract from 515 to 525 tests while keeping SQLite schema 46 unchanged.

## 72.0.44 — 2026-08-04

- Replaced self-authenticating recovery-journal key backups with Ed25519 witness-signed generation-aware v2 documents.
- Bound the secret key, target, audit checkpoint, witness identity, and monotonic journal-key generation into one canonical signature.
- Required a pinned witness public key and external minimum witness receipt before restoring any journal key.
- Rejected forged key-plus-fingerprint backups, wrong witness keys, changed target/checkpoint metadata, unsigned v1 backups, and rollback below either the external witness or current authenticated audit generation.
- Verified pending recovery against its isolated previous keyring and audit snapshot so a damaged live audit does not block legitimate interrupted recovery.
- Added twelve attack and CLI regression tests and expanded the public core contract from 503 to 515 tests while keeping SQLite schema 46 unchanged.

## 72.0.43 — 2026-08-04

- Added status, target-bound private backup, pending-journal-verified restore, and atomic rotation for the recovery-journal HMAC key.
- Refused stale key replacement without a matching pending transaction and blocked rotation while any recovery journal exists.
- Verified manifest HMAC plus the actual previous keyring and audit backup inventory before installing a restored key.
- Rolled back key rotation when authenticated audit recording fails and removed unaudited backup output on failure.
- Added ten key-lifecycle regression tests and expanded the public core contract from 493 to 503 tests while keeping SQLite schema 46 unchanged.

## 72.0.42 — 2026-08-04

- Added a dedicated private recovery-journal HMAC key and authenticated the complete transaction manifest, including state, target, and backup inventory.
- Made signed startup preflight reject missing, replaced, linked, or overly permissive journal keys before restoring any live history file.
- Reclassified v1/v2 journals as unauthenticated legacy state requiring explicit operator confirmation.
- Added nine journal-authentication regression tests and expanded the public core contract from 484 to 493 tests while keeping SQLite schema 46 unchanged.

## 72.0.41 — 2026-08-03

- Added an integrity-inventoried recovery journal with size and SHA-256 checks for the previous history keyring and audit log.
- Made journal cleanup contingent on successful audit-chain and retained-deployment-seal verification.
- Added a signed offline startup preflight that automatically restores one valid interrupted transaction and blocks ambiguous, unsafe, or legacy state.
- Added explicit journal status and manual recovery commands plus safe path quoting in generated launchers.
- Expanded the public core regression contract from 476 to 484 tests while keeping SQLite schema 46 unchanged.

## 72.0.40 — 2026-08-03

- Added a private recovery ZIP that binds the deployment-history keyring, authenticated audit log, external witness receipt, and pinned public-key copy with per-member SHA-256 metadata.
- Required an independently supplied trusted public key and minimum witness during verification and restore, rejecting older witnessed snapshots and rollback below valid current local history.
- Added isolated candidate verification against retained deployment seals and a private rollback journal for interrupted two-file recovery.
- Removed recovery output if the corresponding audit event cannot be committed.
- Expanded the public core regression contract from 467 to 476 tests while keeping SQLite schema 46 unchanged.

## 72.0.39 — 2026-08-03

- Added an external Ed25519 witness receipt that anchors one deployment-history audit sequence and entry hash outside the local rollback boundary.
- Rejected local audit history that is shorter than or diverges from the witnessed prefix while accepting valid newer local events.
- Added protected witness key generation, trusted-public-key verification, standalone signed-kit inclusion, and exact CLI regression coverage.
- Fixed the deployment manager assuming every subcommand exposed `--target`, which broke witness-key generation.
- Expanded the public core regression contract from 459 to 467 tests while keeping SQLite schema 46 unchanged.

## 72.0.38 — 2026-08-03

- Added a versioned current/retired HMAC keyring with atomic retained-deployment resealing during key rotation.
- Added protected mode-0600 keyring backup and fail-closed restore against every retained seal and the full audit chain.
- Added an external chained HMAC audit log for activation, adoption, rollback, pruning, backup, restore, and key rotation.
- Fixed concurrent first-key creation and concurrent audit append sequence races.
- Expanded the public core regression contract from 447 to 459 tests while keeping SQLite schema 46 unchanged.

## 72.0.37 — 2026-08-03

- Added a private deployment-history HMAC key and authenticated whole-tree seals for retained offline deployments.
- Made inventory, rollback selection, and pruning fail closed on code, identity, permission, seal, or history-key changes.
- Added explicit legacy-history adoption with exact installation-ID confirmation while refusing to overwrite an existing invalid seal.
- Sealed the deployment displaced by both signed-kit replacement and explicit rollback.
- Expanded the public core regression contract from 440 to 447 tests while keeping SQLite schema 46 unchanged.

## 72.0.36 — 2026-08-03

- Added validated deployment identity markers, retained-deployment inventory, explicit atomic rollback, and bounded pruning for signed offline installations.
- Fixed failed rollback verification deleting the retained rollback candidate after restoring the active deployment.
- Serialized bootstrap, rollback, and prune with a crash-releasing POSIX advisory lock and rejected unsafe lock-file symlinks.
- Fixed the signed release kit omitting Python modules required by the standalone bootstrap and added an isolated source-tree-independent import contract.
- Expanded the public core regression contract from 431 to 440 tests while keeping SQLite schema 46 unchanged.

## 72.0.35 — 2026-08-03

- Replaced destructive offline `--force` deployment with a private sibling staging tree and same-filesystem atomic activation.
- Kept the existing deployment untouched until signed release, runtime snapshot, installation, two-cycle persistence, SQLite integrity, and schema checks pass.
- Added a post-rename activation cycle, automatic rollback on activation or report failure, and retained the previous deployment in a private sibling path.
- Added bounded release-kit ZIP and runtime-snapshot extraction limits.
- Added eighteen regression tests and expanded the public core regression contract from 413 to 431 tests while keeping SQLite schema 46 unchanged.

## 72.0.34 — 2026-08-03

- Added packaged runtime dependency attestation with off, warn, and fail-closed enforce policies.
- Required exact runtime lock enforcement in the production security profile and production Compose topology.
- Added generated-manifest synchronization checks and platform-specific lock evaluation without adding a new runtime parser dependency.
- Removed obsolete schema 40 constants from distribution and runtime-snapshot rehearsals.
- Changed offline deployment bootstrap schema validation to use the already verified signed release index.
- Expanded the public core regression contract from 405 to 413 tests while keeping SQLite schema 46 unchanged.

## 72.0.33 — 2026-08-03

- Added a clean wheelhouse rehearsal that downloads the exact development lock, records per-run artifact hashes, reinstalls without an index, verifies installed versions, imports the application, and runs focused HTTP tests.
- Split source-only dependency consistency from active-interpreter and clean-install claims; a restricted package index is reported as unavailable rather than accepted as a pass.
- Removed Requests and its dedicated transitive dependencies from the production runtime dependency set while retaining them for development rehearsals.
- Reduced the production image script surface to reviewed offline administration commands.
- Added server-rendered workflow tests for finding updates, import preview/apply/search, and operator-to-approver risk acceptance.
- Expanded the public core regression contract from 397 to 405 tests while keeping SQLite schema 46 unchanged.
- Retained the three Chromium tests as a separate browser acceptance job; the managed local browser policy still prevented local execution.

## 72.0.32 — 2026-08-03

- Routed OSV, CISA KEV, and FIRST EPSS through DNS-pinned bounded JSON transport with private-address and mixed-DNS rejection.
- Added provider-specific response limits, bounded retries, redirect rejection, and process-proxy independence.
- Split integration diagnostics and scanner compatibility services while preserving public imports.
- Added a dependency-free static security boundary audit before Ruff, Bandit, and pip-audit.
- Expanded the public core regression contract from 388 to 397 tests while keeping SQLite schema 46 unchanged.

## 72.0.31 — 2026-08-03

- Extended fail-closed DNS validation and pinned-IP transport to SMTP STARTTLS and implicit TLS while preserving original-host SNI and certificate checks.
- Blocked private and mixed-address SMTP destinations by default, added host allowlisting, and prohibited plain SMTP in production.
- Added strict sender and recipient validation to prevent email header injection.
- Added a mandatory public-CI production Compose rehearsal covering image build, TLS proxy access, restart, persistence, non-root UID, unpublished app port, and internal networking.
- Added a live local-CA SMTP STARTTLS rehearsal and eleven regression tests.
- Expanded the public core regression contract from 377 to 388 tests while keeping SQLite schema 46 unchanged.
- Did not claim a local current-image Docker PASS because Docker was unavailable in the preparation workspace.

## 72.0.30 — 2026-08-03

- Added a pinned HTTP transport for webhook and Jira requests that connects only to policy-validated IP addresses while preserving original-host TLS SNI and certificate checks.
- Blocked private, loopback, link-local, metadata, mixed public/private DNS, URL-credential, and oversized-response destinations by default.
- Added optional hostname allowlisting and production-profile enforcement for private HTTP egress and configured webhooks.
- Added a live local-CA HTTPS egress rehearsal and seven regression tests.
- Expanded the public core regression contract from 370 to 377 tests while keeping SQLite schema 46 unchanged.

## 72.0.29 — 2026-08-03

- Isolated the bounded runtime soak from repository data and required explicit project scope for direct service calls.
- Made SQLite snapshot publication atomic and integrity-checked while preserving an existing backup after failure.
- Added bounded concurrent-write, lock-contention, backup-under-load, process-crash rollback, restore, and audit-integrity rehearsal.
- Expanded the public core regression contract from 365 to 370 tests.
- Kept SQLite schema 46 unchanged.

## 72.0.28 — 2026-08-03

- Split the 750-line database-schema module into version, migration, trigger, search, and backfill boundaries without changing schema 46.
- Added a real local Nginx/Uvicorn HTTPS rehearsal covering TLS 1.2/1.3, redirect, secure cookies, HSTS, database login, and forwarded-client identity.
- Replaced client-supplied forwarded chains at the production edge to prevent login-rate-limit source spoofing.
- Extended the container-equivalent rehearsal for split control/project storage, explicit token scopes, non-root execution, and two-cycle persistence.
- Expanded the public core regression contract from 359 to 365 tests.
- Did not claim a current Docker image or public-certificate deployment because the Docker engine and external PKI were unavailable in this workspace.

## 72.0.27 — 2026-08-03

- Added fail-closed production security profile validation.
- Enforced explicit Bearer token project scopes, including administrator tokens.
- Added session idle expiry and user-agent/client binding with schema 46.
- Added production Docker/Nginx TLS configuration contract and rehearsal.

## 72.0.26 — 2026-08-03

- replaces account-wide lockout with client-scoped sliding-window login failure limits and uniform external authentication failures;
- advances SQLite schema to 45 and clears legacy account lock state;
- adds an offline control-database recovery bundle that excludes sessions and login-attempt history;
- creates a pre-restore safety backup, invalidates all sessions, and preserves project registrations backed by databases still present on disk;
- makes project-scoped storage paths fail closed without an explicit active project;
- expands the public core regression contract from 347 to 353 tests.

## 72.0.25 — 2026-08-02

- separates the control database from the default-project operational database while retaining the legacy source;
- binds recovery bundles to a project identity and blocks cross-project or unscoped restoration by default;
- replaces human-output test success inference with exact pytest exit and collection checks;
- excludes runtime databases, evidence, backups, environment secrets, and private keys from Docker build contexts;
- keeps SQLite table schema 44 and expands the public core regression contract from 342 to 347 tests.

## 72.0.24 — 2026-08-02

- adds original-format anonymization bundles for Nessus, Greenbone XML/CSV, generic CSV, and XLSX pilot samples;
- pseudonymizes structured asset, network, account, URL, UUID, GUID, and MAC identifiers and removes free-text findings;
- rebuilds XLSX files as values-only workbooks and excludes source filenames, source hashes, originals, and alias maps from bundles;
- blocks bundle creation when collected source identifiers remain in the sanitized output;
- adds compatibility and strict profiles, a browser workflow, an offline CLI, and seven regression tests;
- keeps SQLite schema 44 and expands the public core regression contract from 335 to 342 tests.

## 72.0.23 — 2026-08-02

- adds bounded XML node, depth, text-size, attribute, and upload-size checks for scanner XML;
- supports Nessus CPE 2.2 product/version extraction, CVSS v4 scores, host UUIDs, and Greenbone CVE reference attributes;
- detects UTF-8 BOM extensionless XML, semicolon Greenbone CSV, and duplicate canonical scanner rows;
- expands the synthetic scanner corpus from five to nine files and adds six deterministic parser robustness contracts;
- keeps SQLite schema 44 and expands the public core regression contract from 324 to 335 tests.

## 72.0.22 — 2026-08-02

- split the 645-line application service composition root into explicit domain-owned registry groups while preserving all 332 exports;
- split CSV/XLSX parsing, Nessus/OpenVAS adapters, canonical mapping, and preview storage out of the finding-import facade;
- added architecture guardrails for registry ownership, facade dependencies, and tighter module budgets;
- kept SQLite schema 44 and the 324-test public regression contract unchanged.

## 72.0.21 — 2026-08-02

- Added a project-scoped pilot launch center with required and recommended readiness checks.
- Added customer and engagement profiles with audit history and schema 44 validation.
- Added printable executive remediation status reports and a readiness API.
- Added regression coverage for project isolation, schema 43 upgrades, and Korean report downloads.

## 72.0.20 — 2026-08-02

- adds repeatable schema-42 to schema-43 host and Docker upgrade rehearsals;
- adds read-only SMTP and Jira connection diagnostics without delivery side effects;
- adds offline scanner compatibility reports and a five-file synthetic contract matrix;
- fixes missing collaboration runtime exports and strengthens schema-43 backup validation;
- rejects redirects during Jira diagnostics and adds a combined pre-pilot validation command;
- keeps SQLite schema at 43 and expands the public core inventory to 319 tests.

## 72.0.19 — 2026-08-02

- adds project-scoped SMTP notification settings and Jira Cloud issue/comment synchronization;
- encrypts integration credentials with an operator-supplied master key and excludes ciphertext from normal read and template paths;
- adds a leased collaboration outbox, retry policy, daily due-date deduplication, delivery audit records, and scheduled fan-out across projects;
- lets operators create a Jira ticket from a finding and records later workflow, verification, and risk-acceptance events as comments;
- advances SQLite schema to 43 and expands the public core suite to 302 tests.

## 72.0.18 — 2026-08-02

- adds optional project-scoped replication of recovery bundles to a separately mounted filesystem;
- verifies each external copy by SHA-256 and stores an adjacent sidecar before retention pruning;
- adds administrator recovery drills that restore local or external bundles into temporary isolated database and evidence stores;
- reruns SQLite, audit-chain, and evidence-store checks without modifying live project data and retains bounded success or failure reports;
- separates Docker operational data and backup volumes, keeps SQLite schema 42, and expands the public core suite to 294 tests.

## 72.0.17 — 2026-08-02

- migrates every active project database and then verifies evidence and audit integrity independently at startup;
- isolates only damaged projects in read-only mode while healthy projects remain writable;
- fans maintenance, webhook, and recovery-backup scheduling out across active project databases;
- adds administrator integrity recheck, immediate project-backup queuing, project health display, and lifecycle restart after recovery;
- keeps SQLite schema 42 and expands the public core suite to 288 tests.

## 72.0.16 — 2026-08-02

- adds customer/project switching with user membership and explicit Bearer-token project scopes;
- preserves existing data as the default project while placing every new project in a separate SQLite database and storage tree;
- advances the schema to 42 and backfills existing users into the default project;
- processes background jobs across active project queues rather than leaving child-project work queued indefinitely;
- adds ten isolation and upgrade regression tests, expanding the public core suite to 283 tests.

## 72.0.15 — 2026-08-02

- adds a guided finding-import workflow for Nessus `.nessus`, OpenVAS/Greenbone CSV and XML, generic CSV, and XLSX files;
- detects supported formats, previews normalized data, recommends column mappings, and lets operators correct mappings before applying changes;
- supports UTF-8 and common Korean CSV encodings, expands multiple CVEs from one source row, and reports row-level validation failures;
- allows explicit valid-row-only application for incremental imports while refusing partial full snapshots that could incorrectly archive findings;
- stores preview files outside public static paths with actor binding, bounded lifetime, filename sanitization, XML DTD/entity rejection, and XLSX archive preflight checks;
- retains the original direct CSV endpoint for automation compatibility and expands the public core regression suite to 273 tests.

## 72.0.14 — 2026-08-01

- replaces plaintext environment browser accounts and HTTP Basic authentication with database-backed users;
- stores passwords with standard-library scrypt and browser sessions as SHA-256 token digests only;
- adds login, logout, temporary account lockout, session revocation, user administration, and first-admin CLI/bootstrap flows;
- resets the failed-attempt window after an expired lock instead of immediately relocking on the next typo;
- records security-sensitive CLI account changes in the audit chain;
- advances the SQLite schema to 41 and expands the public core regression suite to 264 tests.

## Unreleased read-only recovery mode — 2026-08-01

- starts the authenticated web application in a protected read-only recovery mode when audit-chain or evidence-store integrity cannot be established;
- stops normal mutation, rescoring, checkpoints, cluster registration, workers, schedulers, and sample seeding while the recovery mode is active;
- keeps authenticated reads, SQLite/CSV exports, recovery-bundle validation, and explicit administrator restore operations available;
- exposes degraded health and not-ready readiness signals plus a persistent operator banner and recovery diagnostics;
- converts integrity-check execution errors into bounded diagnostics instead of terminating the process without a recovery surface;
- fixes restore operations in single-node mode so they do not query an uninitialized coordination database, and binds post-restore rescoring to the owning application instance;
- adds five regression tests and expands the public core suite from 249 to 254 tests.

## Unreleased commercial-safety hardening — 2026-07-31

- removes the 2,000-artifact ceiling from evidence-store integrity verification and verifies custody chains in one batched pass;
- adds a regression fixture with 2,001 registered evidence files so valid repositories are not misclassified as containing unregistered files;
- requires explicit demo mode before enabling the loopback administrator fallback, sample-data seeding, the web reset route, or the destructive reset CLI;
- disables the local fallback whenever proxy forwarding headers are present;
- makes production-mode databases start empty instead of automatically mixing synthetic findings with customer data;
- rejects empty or malformed CISA KEV catalogs instead of clearing existing KEV flags;
- defaults Docker Compose CSRF cookies to Secure and documents the direct-local-HTTP override;
- expands the public core regression suite from 244 to 249 tests.

## Unreleased product UI — 2026-07-31

- replaces the feature-first dashboard with a four-step remediation board: 처리 전, 조치 중, 확인 요청, 완료;
- presents Korean workflow labels while retaining the existing internal status model and API values;
- reduces the primary navigation to home, findings, import, and verification, with specialist functions under an administrator menu;
- restructures finding details around the next required action, owner, due date, remediation note, and verification request;
- moves scanner reconciliation, scoring internals, lifecycle records, evidence custody, and recovery functions behind progressive disclosure;
- simplifies CSV onboarding and keeps SBOM, background import, backup, restore, and reset as advanced operations;
- adds product-UX regression coverage and documents the easy-UI product principles.

## Unreleased maintenance — 2026-07-30

- replaces stale `.github/workflows/tests.yml` references with the actual public workflow path;
- makes the dependency-lock validator report a missing public workflow as a consistency issue instead of crashing;
- installs `requirements-dev.lock` in the core CI matrix and runs the dependency-lock smoke check;
- adds a public-scoped release-metadata check that respects the artifacts intentionally excluded from the public repository;
- adds regression coverage without changing application behavior or database schema; the public regression suite increases from 243 to 244 tests.

## 72.0.13 — 2026-07-29

Tag-alignment and metadata-consistency patch release.

- includes the CycloneDX dependency-root correction merged after `v72.0.12`;
- retains the 11/11 release-metadata consistency gate in public CI;
- aligns the repository version, package metadata, application version, Docker tag, citation, lock headers, and CycloneDX application references at `72.0.13`;
- changes no vulnerability-management workflow, database schema, authentication behavior, or Docker runtime behavior;
- keeps the original Windows Docker Desktop validation and its stated limitations as historical evidence.

## 72.0.12 — 2026-07-29

Docker-runtime and public-release maintenance.

- verified the shipped Dockerfile and docker-compose.yml on Windows Docker Desktop;
- confirmed readiness, non-root UID 10001, SQLite schema 40, synthetic API import, restart persistence, container recreation persistence, transactional SQLite backup, and restore into a new named volume;
- retained the 243-test public regression suite, three Chromium E2E flows, cross-platform CI matrix, Ruff fatal checks, Bandit high/high checks, and pip-audit gate;
- documented the validation boundary without claiming customer deployment, production SLA, 24-hour endurance, or Windows runtime-snapshot verification;
- changed only release metadata and public verification documentation after the runtime validation.


## Final public quality maintenance

- expanded the README into a three-step VM demonstration scenario with five repeatable synthetic-data screenshots;
- added a screenshot capture script that uses a temporary SQLite database and does not retain runtime data;
- added a dedicated CI quality job for Python compilation, Ruff fatal rules, Bandit high/high findings, and pip-audit;
- split the 397-line restore validation function into bounded schema-validation helpers without changing restore behavior;
- expanded the public regression suite from 240 to 243 tests.
- fixed the first PR quality run by adding structural context protocols and narrowly scoping Ruff F821 exceptions to the two runtime-injected trust routers;
- raised FastAPI, Starlette, python-multipart, and cryptography to patched dependency baselines before rerunning pip-audit.
- raised Requests from 2.32.5 to 2.33.0 after pip-audit identified PYSEC-2026-2275 in the prior runtime pin.

## Public browser workflow maintenance

- Added three Chromium E2E flows for finding workflow updates, CSV ingestion, and separated operator/approver risk acceptance.
- Added a dedicated Ubuntu/Python 3.13 Playwright CI job instead of multiplying browser downloads across the core OS/Python matrix.
- Added public readiness and regression checks that keep the browser workflow job present.

## Public UI focus maintenance

- Reduced the header to five primary navigation entry points while retaining all existing routes in grouped menus.
- Added a task-first dashboard for immediate findings, overdue work, verification, and active campaigns.
- Moved secondary metrics and advanced filters behind progressive disclosure to reduce first-screen density.
- Added public regression checks for the focused navigation and dashboard workflow.

## Public repository maintenance

- made architecture and submission-readiness checks self-contained in a clean public clone;
- added SHA-256 manifest verification to public CI;
- added Python 3.12 and 3.13 CI coverage with minimal token permissions;
- aligned helper-script Python requirements to 3.12;
- added Dependabot, line-ending policy, and CI status badge;
- shortened the public security-reporting policy and removed upload-only files.
- made every `with connect(...)` transaction close its SQLite handle deterministically, preventing Windows temporary-file locks across recovery, validation and snapshot exports;
- made the ClamAV adapter test cross-platform and converted executable-launch failures into explicit scanner errors;
- expanded public CI to Ubuntu and Windows on Python 3.12 and 3.13.

## 72.0.11 — 2026-07-27

Submission-stabilization release.

- unified user-visible version strings with the application version source;
- replaced the misleading built-in evidence result `CLEAN` with `BASELINE_ONLY`;
- required an explicit administrative exception before baseline-only evidence can be approved or downloaded;
- added submission-readiness checks and public CI maintenance paths;
- measured application line coverage at 79.96% with a 75% release threshold;
- excluded transient runtime databases and coverage data from source provenance fingerprints;
- prepared the public repository with synthetic data and 230 representative tests.

## 72.0.10 — 2026-07-26

- hardened single-host leader election with database-holder and fencing-token checks;
- changed cluster rehearsal to dynamic ports and verified process and instance identity;
- prevented stale local leader state from authorizing scheduled work;
- verified offline bootstrap, restart persistence, upgrade recovery, and cluster failover boundaries.

## 72.0.9 — 2026-07-26

- added a deterministic project ZIP and signed offline release-distribution index;
- added an independent verifier for packaged artifacts and provenance linkage.

## 72.0.8 — 2026-07-26

- added in-toto/SLSA-style release provenance and DSSE Ed25519 rehearsal signing;
- stabilized lifecycle soak cadence and bounded shutdown behavior.

## Earlier development

Earlier releases built the core finding, asset, prioritization, remediation, approval, evidence, audit, background-job, backup, recovery, SBOM, VEX, and OSV workflows. The public repository focuses on the current behavior rather than every historical internal package.

### Post-release metadata correction — 2026-07-29

- corrected the CycloneDX dependency root from `pkg:generic/vulnflow@72.0.8` to `pkg:generic/vulnflow@72.0.12`;
- added a release-metadata consistency gate for version, package, Docker, citation, lock-header, and SBOM references;
- retained application behavior and version `72.0.12`.

### Repository operations policy — 2026-07-30

- changed Dependabot version updates from ungrouped weekly pull requests to grouped monthly minor and patch updates;
- stopped automatic major-version proposals while preserving separate handling for security updates;
- aligned the support document with the repository's restricted public-support model;
- documented the frozen portfolio maintenance and release boundary;
- changed no application version, runtime dependency or VM workflow.

### Public maintenance hotfix follow-up — 2026-07-30

- made the public release-metadata check skip optional browser-test collection when the public release manifest is absent and `--collect-tests` was not requested;
- added regression coverage for forwarding the explicit collection flag into fallback manifest generation;
- changed no application behavior, database schema, VM workflow, or release version.
