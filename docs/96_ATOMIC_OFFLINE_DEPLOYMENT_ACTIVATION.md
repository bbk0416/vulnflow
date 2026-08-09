# Atomic offline deployment activation

VulnFlow 72.0.35 keeps SQLite schema 46 and changes the signed offline
bootstrap from destructive replacement to staged, verified activation.

## Previous failure mode

Before this release, `--force` removed an existing deployment target before the
release public-key fingerprint, signed distribution, runtime snapshot, wheel
installation, service startup, persistence, and SQLite checks had completed.
A bad key, damaged snapshot, incompatible runtime, or failed startup could
therefore erase the last known-good deployment before the replacement was
usable.

## Activation protocol

The bootstrap now creates a private sibling staging directory on the same
filesystem as the requested target:

```text
.<target-name>.staging-<random>
```

The candidate must pass all of the following while the current target remains
untouched:

1. out-of-band release-kit SHA-256 pin;
2. out-of-band Ed25519 public-key fingerprint pin;
3. signed distribution verification;
4. bounded ZIP and runtime-snapshot extraction;
5. offline runtime snapshot restore;
6. wheel installation without an index;
7. two service cycles with authentication and persistence;
8. SQLite integrity and signed-index schema validation.

Only then is the target exchanged with same-filesystem rename operations. The
configuration and launchers are rewritten from the staging root to the final
root, followed by a third post-rename service cycle. That activation cycle must
again pass liveness, readiness, authentication, persistence, bounded shutdown,
SQLite integrity, and schema checks.

## Replacement and rollback

With `--force`, the existing target is renamed to:

```text
.<target-name>.previous-<random>
```

The previous tree is retained after a successful activation and its path is
recorded in the mode-0600 deployment report. If post-rename verification or
final report publication fails, the failed candidate is removed and the
previous tree is restored automatically. A failed fresh installation leaves no
partial target.

Targets that are symbolic links, non-directories, or the filesystem root are
rejected. Operators must stop the existing service before replacement.

`--force` is not an in-place database upgrade. It creates a newly initialized
installation and preserves the old tree for rollback. Production data must be
moved only through the documented backup, control-database recovery, and
cross-version upgrade workflows.

## Archive bounds

The release-kit ZIP rejects:

- more than 4,096 entries;
- duplicate or encrypted entries;
- symbolic links and unsupported file types;
- members larger than 1 GiB;
- more than 2 GiB total uncompressed content;
- compression ratios above 500:1;
- content that expands beyond its declared size.

The platform-specific runtime snapshot separately limits member count and total
uncompressed bytes before file restoration.

## Verification boundary

The public regression suite covers rollback with and without a previous target,
explicit rollback after successful activation, target-symlink rejection,
configuration relocation, staging failure preservation, and archive limits.
The signed offline deployment rehearsal additionally performs a complete fresh
install and a complete forced replacement when the required runtime snapshot is
available.

This does not prove production data migration, running-service handoff,
filesystem crash atomicity on every storage implementation, or Windows offline
runtime installation.
