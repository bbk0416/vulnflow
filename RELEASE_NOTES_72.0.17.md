# VulnFlow 72.0.17 release notes

Release date: 2026-08-02  
SQLite schema: 42 (unchanged)

## Project operations hardening

- runs the current schema migration independently for every active project database before integrity verification;
- verifies audit-chain and evidence-store integrity independently for every active customer/project store at startup;
- places only the affected project in read-only recovery mode instead of stopping healthy projects;
- makes HTTP mutation barriers, background workers, maintenance, webhook delivery, and recovery-backup scheduling honor the selected project's recovery state;
- fans scheduled maintenance, webhook, and recovery-backup jobs out across active project databases;
- lets administrators re-run a project integrity check and queue an immediate project recovery bundle from the project administration screen;
- resumes lifecycle workers when a healthy project becomes available after an all-project read-only startup;
- displays per-project integrity status, bounded diagnostics, and the latest recovery bundle without exposing internal integrity reports;
- preserves schema 42 and the existing default-project upgrade path.

## Verification

- 288 public core regression tests pass in non-overlapping bounded groups;
- 15 project-isolation and project-operations tests pass;
- architecture review passes with 123 application modules, 261 FastAPI routes, and zero internal import cycles;
- public release metadata, dependency lock, CycloneDX SBOM, Python compilation, submission readiness, and SHA-256 repository manifest checks pass.

## Boundaries

- This remains a single-host SQLite product pilot, not a hardened internet-scale multi-tenant SaaS platform.
- A project marked read-only still requires an administrator to diagnose, restore, and re-run integrity verification.
- Chromium E2E execution is not claimed for this workspace because the managed browser blocks local `127.0.0.1` navigation.
- Docker schema-42 upgrade and long-duration multi-project scheduling were not re-run for this release.
