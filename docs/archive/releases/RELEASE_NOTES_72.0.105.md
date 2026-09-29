# VulnFlow Free — Public Beta 72.0.105

Release date: 2026-09-29

72.0.105 is a maintenance release on the feature-frozen 72.0.72 line. It packages the validated post-72.0.104 reliability, release-integrity, first-run, and usability work already merged to `main`. It does not add a new product feature, change SQLite schema 46, or change runtime dependency pins.

## What changed

- Harden release publication so a version can only be published from the exact `main` commit that changes `VERSION`, incomplete releases can only be recovered from their exact tagged commit, and releases from 72.0.105 onward must report GitHub native `immutable=true`.
- Snapshot the 36 legacy GitHub Releases / 40 legacy assets that predate native immutability by asset name, size, and GitHub API SHA-256 digest; validate that evidence in the required `static-quality / Python 3.13` path and again on `main`.
- Make coverage collection deterministic by waiting for the parallel coverage data flush instead of relying on a fixed delay.
- Make the Linux/macOS launcher reuse a healthy locked `.venv` when the `requirements.lock` SHA-256 and installed runtime still match, while retaining reinstall/repair behavior on drift.
- Add a normal-auth first-run regression covering split storage preparation, zero-user state, administrator creation, password authentication, and browser login.
- Clarify the first administrator username (`admin`) in local launchers and explain in the import preview that remediation priority is not based on CVSS alone.
- Keep the product flow and scoring policy unchanged: scanner import → assign → remediate → verify → close.

## Verification boundary

- Public regression collection contract remains 731 tests across seven bounded groups.
- Protected public CI still requires 12 contexts on the exact pull-request head; CodeQL `Analyze (actions)` and `Analyze (python)` are also required before publication.
- Windows/Python 3.13 builds and re-verifies the exact-tree Windows release candidate.
- SQLite schema remains 46 and runtime dependency pins remain unchanged.
- The post-72.0.104 line was additionally exercised on a clean maintainer-operated LG Windows environment through install, login, scanner import, assignment, remediation, two complete-snapshot absences, verification approval, and final `CLOSED` state. This is maintainer-operated product verification, not external customer validation.
- 24-hour endurance, sustained production-scale capacity, rootless Docker, Kubernetes, and real external proxy/NAS/firewall/ACL environments remain outside the claimed verification boundary.
