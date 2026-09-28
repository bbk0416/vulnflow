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
LEGACY_RELEASE_ASSET_EVIDENCE_CAPTURED_AT = "2026-09-28"
LEGACY_RELEASE_ASSET_EVIDENCE: dict[str, tuple[tuple[str, str, int], ...]] = {
    "v72.0.104": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.104.zip", "sha256:7c06253a2fec0e808482af317638c26e324be90eda0f4ff8b65404018b11bd4e", 3116084),
    ),
    "v72.0.103": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.103.zip", "sha256:ce167e3cb63a65a7b7690181ffe095db2c2b81ab24d4f1f2076b67515aba11f0", 3166816),
    ),
    "v72.0.102": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.102.zip", "sha256:96cfb8282f9fb60ffc0ec6c26b2625526370be89367b6fb32c9f96e7a98e4030", 3095552),
    ),
    "v72.0.101": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.101.zip", "sha256:ffa6284394efb3a08d6a3d37d6febbcb98dd544b3fc43052e944a9745c36f668", 3087740),
    ),
    "v72.0.100": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.100.zip", "sha256:829334f3d46bae3e3369d6a163be15c0d93bc60635c9338f690456bdac243727", 3085969),
    ),
    "v72.0.99": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.99.zip", "sha256:89cf3545e549da822bee4d697e6745b6c82e852489bfbc51ac8db7f5575758fd", 3088237),
    ),
    "v72.0.98": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.98.zip", "sha256:c3b5062594713c91949616fd21bcfc91cd33478268b9bf23711c2caeecab06a3", 3080901),
    ),
    "v72.0.97": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.97.zip", "sha256:265f0517a02ea67e05084fc02794566f4f1925ce6ab8ce95406d9986e2fe0f50", 3078824),
    ),
    "v72.0.96": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.96.zip", "sha256:219be90fcd42c4944964444383c847a59530e0679614c1afe8a7b18d3f562782", 3077272),
    ),
    "v72.0.95": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.95.zip", "sha256:30b452b4dbcb03e396159a8b1dae242c01bde3105f6e4d7ff4e5400a2d89aaa8", 3075164),
    ),
    "v72.0.94": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.94.zip", "sha256:f068340e200f898542104ab886e3aac1303f14baa778bf4f132bfdf6f1c50397", 3072919),
    ),
    "v72.0.93": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.93.zip", "sha256:5e1c5a122d2cc92e537e45a35f695de1ae0fc94307b70ede8c3130b9b265602f", 3081903),
    ),
    "v72.0.92": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.92.zip", "sha256:7168ef1bd3862bed8a14814d7082ad10f923a18a5e61c5101d2d3fd52452bdb2", 3069427),
    ),
    "v72.0.91": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.91.zip", "sha256:4698df4919ff4f48f442179b62b7d2c4df967651f947f7ca88c5510742bb0f4f", 3072849),
    ),
    "v72.0.90": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.90.zip", "sha256:94cd567b2d6dfd421c49791e5ed08f4fdfe76941bb1a4f12cde64b58aecdc3de", 3065027),
    ),
    "v72.0.89": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.89.zip", "sha256:4f13738f9bb7ad430dede9c4d811f8a11e11fb201b2b45ba16fdffaae83d9394", 3063356),
    ),
    "v72.0.88": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.88.zip", "sha256:5b754ef61c7a2acf6eeee932ff330f801b2e9dd484f0533cbb46e3ed62a882c7", 3073314),
    ),
    "v72.0.87": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.87.zip", "sha256:aebb6dc904b87b8627d69fcbbc0159426f5b2e5214e5d2817aa429537204e14a", 3058833),
    ),
    "v72.0.86": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.86.zip", "sha256:089946987de2e7d663737d78121273fe26613078f704f076e436f241322796c9", 3056264),
    ),
    "v72.0.85": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.85.zip", "sha256:31942037163d1eac498b82fc0e85482ce69c5d862618d4479d4c209fb2432141", 3054157),
    ),
    "v72.0.84": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.84.zip", "sha256:0acae506d06948fb9e547476d4ee1be85564fab83208c28205e99946346a4d72", 3052562),
    ),
    "v72.0.83": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.83.zip", "sha256:c8f6493c2caaa0dfcac6cff9937204d6a542fa7880eb7cd71e6c41c677f29711", 3062548),
    ),
    "v72.0.82": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.82.zip", "sha256:1aae9aee5473099052b05537a8d6690f432965ce6654a39c27376a93daf169c8", 3095781),
    ),
    "v72.0.81": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.81.zip", "sha256:6387eb072b13551d3c2eedf264fb49181ef3d692fc317187e2c33ebba8f4b976", 3042176),
    ),
    "v72.0.80": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.80.zip", "sha256:06a0e0764082e77f23fdf8d2bfbb46ff480df0c4af57488e078ce52b360510ab", 3037138),
    ),
    "v72.0.79": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.79.zip", "sha256:fb3290e5a5808a472bca16d2e970569b3007f11cea9a55af735e20a3a3e32584", 3033295),
    ),
    "v72.0.78": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.78.zip", "sha256:8278b23eb5d919d52742739ff1eecd8f6f59ed2505115152b2da55b9e4d2b6b0", 3029825),
    ),
    "v72.0.77": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.77.zip", "sha256:c1319109094331bc219bbc88547a8eb005f771e6788d191535d9e9105d8267e1", 3026433),
    ),
    "v72.0.76": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.76.zip", "sha256:82418be0c620928423b2b2d369e24604659c27ae8ab4726950d27f7d230ba1ba", 3028826),
    ),
    "v72.0.75": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.75.zip", "sha256:0f6b38d3d26b685bf3259227b4af07ad018f54a9c30e23e641d846a2373b9c85", 3066434),
    ),
    "v72.0.74": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.74.zip", "sha256:bf12f49e1841301538e754f5b8b5ef73960c1c59c92e9febca21736170e51e3c", 3021770),
    ),
    "v72.0.73": (
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.73.zip", "sha256:45b4513ec994339bdb28dc60deba4c4717cce6bb8f68fc1f0801911582e64d65", 3019749),
    ),
    "v72.0.72": (
        ("bbk_vulnflow-72.0.72-py3-none-any.whl", "sha256:63859ec476a474fb3b50f185b23c64f17f0724a8f3301fd1313e0f316e095869", 577431),
        ("bbk_vulnflow-72.0.72.tar.gz", "sha256:94ca7af8d99b2ae960240d0e844ead76a67b19eef041e8beb4d5be7097ed4c51", 2543887),
        ("SHA256SUMS_RELEASE.txt", "sha256:cb49f8a763ba636bd0b2798743a0ae4a9ee807c6300c4617af044699d1a4d04a", 423),
        ("VulnFlow_72.0.72_PR18_Final_CI_Closure_Evidence.zip", "sha256:75ff146fdff0cd99b35ea3aeb76f99a214f6a6b166915b4ae0ab10181529160e", 3881),
        ("VulnFlow_Free_Public_Beta_Windows_Core_72.0.72.zip", "sha256:b5da684b3ceb2e1058d5aac658f003db771b9183b0d39afe359a0bfc928524b6", 2990498),
        ("vulnflow-pilot-completion-freeze-v62.zip", "sha256:f3ef2565bc9703d857367310407014773bc46f2b1461b30ff619b3f4fac14719", 3018303),
    ),
    "v72.0.13": (
        ("VulnFlow_72.0.13_RELEASE_VERIFICATION.txt", "sha256:8e85025e200a10b968a65ddc813383f10a670f8a469a3f4ec3e045e002a78049", 908),
    ),
    "v72.0.12": (
        ("VulnFlow_72.0.12_DOCKER_VALIDATION_SUMMARY.txt", "sha256:5bea523915737474120ecb6f8a86a234411fba7df5de393bbca7e31d896a0ac7", 1121),
    ),
    "v72.0.11": (
    ),
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
    tag = f"v{version}"
    expected_assets = LEGACY_RELEASE_ASSET_EVIDENCE.get(tag)
    if expected_assets is None:
        return True
    expected_name = f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip"
    expected_digest = next(
        (digest for name, digest, _size in expected_assets if name == expected_name),
        None,
    )
    return expected_digest is None or actual_digest == expected_digest


def validate_legacy_release_asset_evidence(
    releases: list[dict[str, object]],
    *,
    expected: dict[str, tuple[tuple[str, str, int], ...]] = LEGACY_RELEASE_ASSET_EVIDENCE,
) -> None:
    by_tag = {
        release.get("tag_name"): release
        for release in releases
        if isinstance(release.get("tag_name"), str)
    }
    missing = sorted(tag for tag in expected if tag not in by_tag)
    if missing:
        raise ReleaseStateError(f"legacy GitHub Release missing: {missing}")

    for tag, expected_assets in expected.items():
        release = by_tag[tag]
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            raise ReleaseStateError(f"legacy release assets malformed for {tag}")
        observed: list[tuple[str, str, int]] = []
        for asset in assets:
            if not isinstance(asset, dict):
                raise ReleaseStateError(f"legacy release asset malformed for {tag}")
            name = asset.get("name")
            digest = asset.get("digest")
            size = asset.get("size")
            if not isinstance(name, str) or not isinstance(digest, str) or not isinstance(size, int):
                raise ReleaseStateError(f"legacy release asset metadata incomplete for {tag}")
            observed.append((name, digest, size))
        if tuple(sorted(observed)) != tuple(sorted(expected_assets)):
            raise ReleaseStateError(
                f"legacy release asset evidence drift for {tag}: "
                f"expected={tuple(sorted(expected_assets))} observed={tuple(sorted(observed))}"
            )


def _all_releases(repo: str, token: str) -> list[dict[str, object]]:
    releases: list[dict[str, object]] = []
    page = 1
    while True:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "vulnflow-release-state",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                batch = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ReleaseStateError(
                f"GitHub releases lookup failed: HTTP {exc.code}: {body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ReleaseStateError(f"GitHub releases lookup failed: {exc}") from exc
        if not isinstance(batch, list):
            raise ReleaseStateError("GitHub releases lookup returned malformed data")
        releases.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < 100:
            return releases
        page += 1


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
    parser.add_argument("--legacy-evidence-only", action="store_true")
    args = parser.parse_args()

    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    tag = f"v{version}"
    asset_name = f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip"
    expected_title = f"VulnFlow Free - Public Beta (Core {version})"
    immutable_required = requires_native_immutability(version)

    legacy_releases = _all_releases(repo, token)
    validate_legacy_release_asset_evidence(legacy_releases)
    legacy_release_evidence_valid = True
    if args.legacy_evidence_only:
        asset_count = sum(
            len(release.get("assets", []))
            for release in legacy_releases
            if isinstance(release.get("assets"), list)
        )
        print(json.dumps({
            "legacy_release_evidence_captured_at": LEGACY_RELEASE_ASSET_EVIDENCE_CAPTURED_AT,
            "legacy_release_evidence_valid": True,
            "legacy_release_count": len(LEGACY_RELEASE_ASSET_EVIDENCE),
            "legacy_release_asset_count": asset_count,
        }, sort_keys=True))
        return

    sha = os.environ["GITHUB_SHA"]
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
        "legacy_release_evidence_valid": legacy_release_evidence_valid,
        "legacy_release_evidence_captured_at": LEGACY_RELEASE_ASSET_EVIDENCE_CAPTURED_AT,
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
