from __future__ import annotations

"""Resolve whether a main-branch commit may publish or repair a release."""

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE_IMMUTABLE_RELEASE_FLOOR = (72, 0, 105)
LEGACY_MUTABLE_RELEASE_ASSET_DIGESTS = {
    "72.0.104": "sha256:7c06253a2fec0e808482af317638c26e324be90eda0f4ff8b65404018b11bd4e",
}


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
    asset_integrity_valid: bool = True,
) -> PublicationDecision:
    if tag_exists:
        if release_exists:
            if not release_metadata_valid:
                raise ReleaseStateError("existing release metadata does not match the canonical release identity")
            if asset_exists and not asset_integrity_valid:
                raise ReleaseStateError("existing release asset digest does not match the recorded release evidence")
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


def legacy_asset_digest_valid(version: str, actual_digest: str | None) -> bool:
    expected = LEGACY_MUTABLE_RELEASE_ASSET_DIGESTS.get(version)
    return expected is None or actual_digest == expected


def _sha256_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def requires_native_immutability(version: str) -> bool:
    try:
        parts = tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise ReleaseStateError(f"invalid VERSION for immutable-release policy: {version}") from exc
    if len(parts) != 3:
        raise ReleaseStateError(f"invalid VERSION for immutable-release policy: {version}")
    return parts >= NATIVE_IMMUTABLE_RELEASE_FLOOR


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
            "X-GitHub-Api-Version": "2026-03-10",
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
    immutable_required = requires_native_immutability(version)

    tag_exists = _tag_exists(tag)
    release = _release(repo, tag, token)
    release_exists = release is not None
    asset_exists = False
    release_asset_digest: str | None = None
    release_immutable = False
    metadata_valid = False

    if release is not None:
        assets = release.get("assets", [])
        matching_asset = next(
            (
                asset
                for asset in assets
                if isinstance(asset, dict) and asset.get("name") == asset_name
            ),
            None,
        ) if isinstance(assets, list) else None
        asset_exists = matching_asset is not None
        if matching_asset is not None and isinstance(matching_asset.get("digest"), str):
            release_asset_digest = matching_asset["digest"]
        release_immutable = release.get("immutable") is True
        metadata_valid = (
            release.get("tag_name") == tag
            and release.get("name") == expected_title
            and release.get("draft") is False
            and release.get("prerelease") is False
            and (not immutable_required or release_immutable)
        )

    tag_targets_sha = _tag_targets_sha(tag, sha) if tag_exists else False
    version_changed = _version_changed(sha) if not tag_exists else False
    asset_integrity_valid = (
        not asset_exists or legacy_asset_digest_valid(version, release_asset_digest)
    )
    decision = decide_publication(
        tag_exists=tag_exists,
        release_exists=release_exists,
        asset_exists=asset_exists,
        tag_targets_sha=tag_targets_sha,
        version_changed=version_changed,
        release_metadata_valid=metadata_valid,
        asset_integrity_valid=asset_integrity_valid,
    )

    payload = {
        "version": version,
        "tag": tag,
        "tag_exists": tag_exists,
        "release_exists": release_exists,
        "asset_exists": asset_exists,
        "release_asset_digest": release_asset_digest,
        "asset_integrity_valid": asset_integrity_valid,
        "tag_targets_sha": tag_targets_sha,
        "version_changed": version_changed,
        "release_metadata_valid": metadata_valid,
        "release_immutable": release_immutable,
        "immutable_required": immutable_required,
        "publish": decision.publish,
        "create_tag": decision.create_tag,
        "release_mode": decision.mode,
    }
    print(json.dumps(payload, sort_keys=True))

    if args.require_complete:
        if decision.mode != "complete":
            raise ReleaseStateError(f"release is not complete: {json.dumps(payload, sort_keys=True)}")
        local_asset = ROOT / "dist" / asset_name
        if not local_asset.is_file():
            raise ReleaseStateError(f"local release asset is missing: {local_asset}")
        local_digest = _sha256_digest(local_asset)
        if release_asset_digest != local_digest:
            raise ReleaseStateError(
                f"published release asset digest mismatch: API={release_asset_digest} local={local_digest}"
            )
    if args.github_output:
        _write_outputs(Path(args.github_output), version=version, decision=decision)


if __name__ == "__main__":
    main()
