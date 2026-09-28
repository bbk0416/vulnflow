from __future__ import annotations

"""Resolve whether a main-branch commit may publish or repair a release."""

from dataclasses import dataclass
import argparse
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class ReleaseStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicationDecision:
    publish: bool
    create_tag: bool
    mode: str


def decide_publication(
    *,
    tag_exists: bool,
    release_exists: bool,
    asset_exists: bool,
    tag_targets_sha: bool,
    version_changed: bool,
    release_metadata_valid: bool,
) -> PublicationDecision:
    if tag_exists:
        if release_exists:
            if not release_metadata_valid:
                raise ReleaseStateError("existing release metadata does not match the canonical release identity")
            if asset_exists:
                return PublicationDecision(publish=False, create_tag=False, mode="complete")
            if not tag_targets_sha:
                raise ReleaseStateError("incomplete release may only be repaired from its exact tagged commit")
            return PublicationDecision(publish=True, create_tag=False, mode="upload")

        if not tag_targets_sha:
            raise ReleaseStateError("orphan release tag may only be repaired from its exact tagged commit")
        return PublicationDecision(publish=True, create_tag=False, mode="create")

    if release_exists:
        raise ReleaseStateError("GitHub Release exists without the immutable version tag")

    if not version_changed:
        raise ReleaseStateError(
            "unpublished version may only be published from the main commit that changes VERSION"
        )

    return PublicationDecision(publish=True, create_tag=True, mode="create")


def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _tag_exists(tag: str) -> bool:
    result = _run_git("ls-remote", "--exit-code", "origin", f"refs/tags/{tag}")
    if result.returncode == 0:
        return True
    if result.returncode == 2:
        return False
    raise ReleaseStateError(result.stderr.strip() or f"failed to inspect remote tag {tag}")


def _tag_targets_sha(tag: str, sha: str) -> bool:
    fetch = _run_git("fetch", "--force", "origin", f"+refs/tags/{tag}:refs/tags/{tag}")
    if fetch.returncode != 0:
        raise ReleaseStateError(fetch.stderr.strip() or f"failed to fetch {tag}")
    target = _run_git("rev-list", "-n", "1", tag)
    if target.returncode != 0:
        raise ReleaseStateError(target.stderr.strip() or f"failed to resolve {tag}")
    return target.stdout.strip() == sha


def _version_changed(sha: str) -> bool:
    result = _run_git("diff", "--quiet", f"{sha}^", sha, "--", "VERSION")
    if result.returncode == 0:
        return False
    if result.returncode == 1:
        return True
    raise ReleaseStateError(result.stderr.strip() or "failed to inspect VERSION change")


def _release(repo: str, tag: str, token: str) -> dict[str, object] | None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/tags/{tag}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vulnflow-release-state",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        body = exc.read().decode("utf-8", errors="replace")
        raise ReleaseStateError(f"GitHub release lookup failed: HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise ReleaseStateError(f"GitHub release lookup failed: {exc}") from exc


def _write_outputs(path: Path, *, version: str, decision: PublicationDecision) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"version={version}\n")
        handle.write(f"publish={'true' if decision.publish else 'false'}\n")
        handle.write(f"create_tag={'true' if decision.create_tag else 'false'}\n")
        handle.write(f"release_mode={decision.mode}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve the exact release publication/recovery state.")
    parser.add_argument("--github-output", default="")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    token = os.environ["GITHUB_TOKEN"]
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    tag = f"v{version}"
    asset_name = f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip"
    expected_title = f"VulnFlow Free - Public Beta (Core {version})"

    tag_exists = _tag_exists(tag)
    release = _release(repo, tag, token)
    release_exists = release is not None
    asset_exists = False
    metadata_valid = False

    if release is not None:
        asset_exists = any(
            isinstance(asset, dict) and asset.get("name") == asset_name
            for asset in release.get("assets", [])
            if isinstance(release.get("assets"), list)
        )
        metadata_valid = (
            release.get("tag_name") == tag
            and release.get("name") == expected_title
            and release.get("draft") is False
            and release.get("prerelease") is False
        )

    tag_targets_sha = _tag_targets_sha(tag, sha) if tag_exists else False
    version_changed = _version_changed(sha) if not tag_exists else False
    decision = decide_publication(
        tag_exists=tag_exists,
        release_exists=release_exists,
        asset_exists=asset_exists,
        tag_targets_sha=tag_targets_sha,
        version_changed=version_changed,
        release_metadata_valid=metadata_valid,
    )

    payload = {
        "version": version,
        "tag": tag,
        "tag_exists": tag_exists,
        "release_exists": release_exists,
        "asset_exists": asset_exists,
        "tag_targets_sha": tag_targets_sha,
        "version_changed": version_changed,
        "release_metadata_valid": metadata_valid,
        "publish": decision.publish,
        "create_tag": decision.create_tag,
        "release_mode": decision.mode,
    }
    print(json.dumps(payload, sort_keys=True))

    if args.require_complete and decision.mode != "complete":
        raise ReleaseStateError(f"release is not complete: {json.dumps(payload, sort_keys=True)}")
    if args.github_output:
        _write_outputs(Path(args.github_output), version=version, decision=decision)


if __name__ == "__main__":
    main()
