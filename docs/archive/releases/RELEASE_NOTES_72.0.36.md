# VulnFlow 72.0.36 release notes

VulnFlow 72.0.36 keeps SQLite schema 46 and closes the retained-deployment
lifecycle and standalone release-kit dependency gaps left after atomic offline
activation.

## Fixed defects

- Prevented unlimited unmanaged growth of validated previous deployments by
  adding a default three-version retention policy.
- Added an inventory and explicit rollback/prune CLI for retained offline
  deployments.
- Fixed failed rollback verification deleting the rollback candidate even after
  the current deployment had been restored.
- Serialized bootstrap, rollback, and prune with a crash-releasing POSIX
  advisory lock and rejected unsafe lock-file symlinks.
- Fixed the signed release kit shipping the bootstrap without all Python modules
  required to import it outside the source repository.

## Deployment identity and safe automation

New deployments receive a private identity marker containing the installation
ID, application/schema version, pinned kit hash, pinned release-key fingerprint,
installation time, and target name. Only validated marker-bearing directories
are automatically listed or pruned. Unknown legacy paths remain untouched.

Rollback uses atomic same-filesystem activation and the existing live service,
authentication, persistence, shutdown, schema, and SQLite integrity checks. A
failed rollback restores both the current target and the retained candidate.

Retention is post-commit: pruning failure cannot invalidate an already verified
activation after older directories may have been removed.

## Signed distribution contract

The release index now requires and signs:

- offline activation helper;
- deployment history helper;
- offline bootstrap;
- deployment management CLI.

An isolated regression executes the bootstrap and manager with only those
release-kit files present.

## Verification scope

The schema remains 46. The new tests cover identity validation, unmanaged
legacy preservation, deterministic inventory order, bounded prune, successful
rollback, failed rollback candidate preservation, concurrent-operation locking,
unsafe lock symlinks, and standalone release-kit imports.

Full signed-kit execution still requires the exact platform runtime snapshot and
production dependency lock. Docker, Chromium, real customer scanner exports,
and long-duration production endurance remain separate acceptance boundaries.
