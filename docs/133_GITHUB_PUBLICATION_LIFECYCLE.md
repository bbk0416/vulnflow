# GitHub publication lifecycle

VulnFlow keeps release verification and GitHub publication as separate trust
boundaries.

`scripts/release_orchestrator.py` remains the bounded, resumable local release
verification engine. Git/GitHub mutation is centralized in
`scripts/publication_lifecycle.py`.

The publication runner is deliberately inert unless `--apply` is supplied.
A JSON contract binds the repository, exact base SHA, working branch, allowed
changed paths, local checks, CI check count, immutable tags, immutable release
assets, commit message, and pull-request metadata.

The lifecycle is:

1. verify origin, exact base SHA, branch ancestry, immutable tags and release assets;
2. fail closed if the working tree contains a path outside `allowed_paths`;
3. stage only the declared paths and regenerate `SHA256SUMS.txt` from the Git index;
4. run `git diff --cached --check` and the contract's local validation commands;
5. commit once and journal the exact commit SHA;
6. push or prove the exact branch head is already present;
7. create or reuse the pull request bound to that exact head;
8. wait for the pull-request workflow associated with that exact head and require
   the declared number of passing checks;
9. re-fetch the base branch and refuse automatic merge if its SHA changed;
10. squash-merge with GitHub's exact-head guard;
11. re-fetch and verify the merge SHA, changed-path boundary, public manifest,
    immutable tags, and immutable release assets.

The journal is stored outside the repository by default and is keyed by a
SHA-256 fingerprint of the normalized publication contract. Re-running the
same contract can resume proven completed steps. A journal from another
contract is rejected.

Example dry run:

```text
python scripts/publication_lifecycle.py --contract publication.json
```

Mutation requires explicit opt-in:

```text
python scripts/publication_lifecycle.py --contract publication.json --apply
```

This command is intended to replace one-off release/evidence GitHub mutation
runners. It does not replace scanner validation, release artifact construction,
or the existing local release verification orchestrator.
