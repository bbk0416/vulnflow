# VulnFlow 72.0.34 release notes

VulnFlow 72.0.34 keeps SQLite schema 46 and closes two release-safety gaps:
runtime dependency drift was not checked by the application itself, and three
offline distribution rehearsals still compared installed databases with the
obsolete schema 40 constant.

## Runtime dependency attestation

- Packages a generated `app/resources/runtime_dependency_lock.json` derived
  from `requirements.lock`.
- Adds `VULNFLOW_RUNTIME_DEPENDENCY_POLICY=off|warn|enforce`.
- Requires `enforce` in the production security profile and production Compose.
- Refuses production startup when an active locked package is missing or has a
  different installed version.
- Keeps development default `off` so source review and restricted workspaces do
  not falsely claim a lock-matching interpreter.
- Adds a CI check that the packaged manifest is still identical to the source
  runtime lock.

This check verifies installed versions. It does not replace the clean
wheelhouse download and offline reinstall gate, artifact hashes, or an
advisory vulnerability audit.

## Release schema drift removal

- `distribution_artifact_rehearsal.py` and
  `runtime_dependency_snapshot.py` now use the central schema version source.
- `offline_deployment_bootstrap.py` obtains the expected schema from the
  already verified signed release index rather than a local hardcoded value.
- The offline deployment report records both the installed and expected schema.
- Distribution, runtime-snapshot, and offline-bootstrap rehearsals now configure explicit control and default-project database paths and inspect the real project DB instead of an empty legacy `VULNFLOW_DB`.

Before this change, the three tools still expected schema 40 while the current
application creates schema 46, so a complete release or offline deployment
rehearsal could reject a correct current installation. The previous single-DB probe also read schema 0 from an unused legacy path after split storage; the corrected distribution artifact rehearsal now passes 26/26.

## Verification scope

- Adds eight regression tests for manifest synchronization, platform-specific
  dependencies, missing and drifted packages, production fail-closed policy,
  signed-index schema selection, and obsolete schema constant removal.
- Expands the public core regression contract from 405 to 413 tests.
- Keeps the three Chromium tests separate from the server/domain suite.

The live Nginx/Uvicorn TLS transport rehearsal now runs with the pilot profile and dependency policy `warn`, while the production profile and dependency `enforce` contract are verified separately. This prevents the known shared-interpreter drift from masking TLS, cookie, and proxy-header checks without weakening the production startup rule.

The preparation workspace still cannot download the exact wheelhouse, run the
current Docker Compose topology, or bypass its managed Chromium navigation
policy. Those items remain CI or authorized-environment gates rather than local
passes.
