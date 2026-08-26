from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_JOURNAL_DIR = Path(tempfile.gettempdir()) / "vulnflow-publication-lifecycle"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LifecycleError(RuntimeError):
    pass


def _canon_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def contract_fingerprint(contract: dict[str, Any]) -> str:
    return hashlib.sha256(_canon_json(contract)).hexdigest()


def normalize_repo_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError("repository path must be a non-empty string")
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise LifecycleError(f"unsafe repository path: {value}")
    normalized = str(path)
    if normalized in {"", "."}:
        raise LifecycleError(f"unsafe repository path: {value}")
    return normalized


def _require_string(contract: dict[str, Any], name: str) -> str:
    value = contract.get(name)
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{name} must be a non-empty string")
    return value.strip()


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != SCHEMA_VERSION:
        raise LifecycleError(f"unsupported schema: {contract.get('schema')!r}")

    normalized = dict(contract)
    normalized["repository"] = _require_string(contract, "repository")
    normalized["base_branch"] = _require_string(contract, "base_branch")
    normalized["base_sha"] = _require_string(contract, "base_sha").lower()
    normalized["working_branch"] = _require_string(contract, "working_branch")
    normalized["commit_message"] = _require_string(contract, "commit_message")
    normalized["pr_title"] = _require_string(contract, "pr_title")
    normalized["pr_body"] = _require_string(contract, "pr_body")

    if not HEX40.fullmatch(normalized["base_sha"]):
        raise LifecycleError("base_sha must be a 40-character lowercase Git SHA")

    allowed = contract.get("allowed_paths")
    if not isinstance(allowed, list) or not allowed:
        raise LifecycleError("allowed_paths must be a non-empty list")
    paths = [normalize_repo_path(str(item)) for item in allowed]
    if len(paths) != len(set(paths)):
        raise LifecycleError("allowed_paths contains duplicates")
    normalized["allowed_paths"] = sorted(paths)

    manifest = contract.get("manifest", {})
    if not isinstance(manifest, dict):
        raise LifecycleError("manifest must be an object")
    manifest_path = normalize_repo_path(str(manifest.get("path", "SHA256SUMS.txt")))
    if manifest_path not in normalized["allowed_paths"]:
        raise LifecycleError("manifest path must be included in allowed_paths")
    normalized["manifest"] = {
        "path": manifest_path,
        "regenerate": bool(manifest.get("regenerate", True)),
    }

    check_count = contract.get("ci_check_count", 8)
    if not isinstance(check_count, int) or check_count < 1:
        raise LifecycleError("ci_check_count must be a positive integer")
    normalized["ci_check_count"] = check_count

    local_checks = contract.get("local_checks", [])
    if not isinstance(local_checks, list):
        raise LifecycleError("local_checks must be a list")
    normalized_checks: list[list[str]] = []
    for command in local_checks:
        if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
            raise LifecycleError("each local_checks entry must be a non-empty argv list")
        normalized_checks.append(command)
    normalized["local_checks"] = normalized_checks

    tags = contract.get("immutable_tags", {})
    if not isinstance(tags, dict):
        raise LifecycleError("immutable_tags must be an object")
    clean_tags: dict[str, str] = {}
    for tag, sha in tags.items():
        if not isinstance(tag, str) or not tag:
            raise LifecycleError("immutable tag name must be non-empty")
        if not isinstance(sha, str) or not HEX40.fullmatch(sha.lower()):
            raise LifecycleError(f"immutable tag SHA is invalid: {tag}")
        clean_tags[tag] = sha.lower()
    normalized["immutable_tags"] = clean_tags

    assets = contract.get("immutable_release_assets", [])
    if not isinstance(assets, list):
        raise LifecycleError("immutable_release_assets must be a list")
    clean_assets = []
    for item in assets:
        if not isinstance(item, dict):
            raise LifecycleError("release asset contract must be an object")
        tag = str(item.get("tag", "")).strip()
        name = str(item.get("name", "")).strip()
        sha = str(item.get("sha256", "")).lower().strip()
        if not tag or not name or not HEX64.fullmatch(sha):
            raise LifecycleError("invalid immutable release asset contract")
        clean_assets.append({"tag": tag, "name": name, "sha256": sha})
    normalized["immutable_release_assets"] = clean_assets

    method = contract.get("merge_method", "squash")
    if method != "squash":
        raise LifecycleError("only squash merge is supported")
    normalized["merge_method"] = method
    normalized["delete_branch"] = bool(contract.get("delete_branch", True))
    return normalized


def load_contract(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise LifecycleError(f"cannot read contract: {exc}") from exc
    if not isinstance(raw, dict):
        raise LifecycleError("contract root must be an object")
    return validate_contract(raw)


def _run(
    args: list[str],
    *,
    cwd: Path,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(args), flush=True)
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if capture:
        if proc.stdout:
            print(proc.stdout.rstrip(), flush=True)
        if proc.stderr:
            print(proc.stderr.rstrip(), flush=True)
    if check and proc.returncode:
        raise LifecycleError(f"command failed rc={proc.returncode}: {' '.join(args)}")
    return proc


def _text(args: list[str], *, cwd: Path) -> str:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise LifecycleError(
            f"command failed rc={proc.returncode}: {' '.join(args)}\n{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def _bytes(args: list[str], *, cwd: Path) -> bytes:
    proc = subprocess.run(args, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise LifecycleError(f"binary command failed rc={proc.returncode}: {' '.join(args)}")
    return proc.stdout


def _git_blob(repo: Path, spec: str) -> bytes:
    return _bytes(["git", "show", spec], cwd=repo)


def _origin_matches_repository(origin: str, repository: str) -> bool:
    origin = origin.strip().removesuffix(".git")
    repository = repository.strip().strip("/")
    return (
        origin.endswith("/" + repository)
        or origin.endswith(":" + repository)
        or origin == repository
    )


def current_changed_paths(repo: Path) -> set[str]:
    raw = _bytes(["git", "status", "--porcelain=v1", "-z"], cwd=repo)
    fields = [item for item in raw.split(b"\0") if item]
    paths: set[str] = set()
    i = 0
    while i < len(fields):
        entry = fields[i].decode("utf-8", errors="strict")
        status = entry[:2]
        path = entry[3:]
        if status[0] in {"R", "C"} or status[1] in {"R", "C"}:
            i += 1
            if i >= len(fields):
                raise LifecycleError("malformed porcelain rename/copy record")
            path = fields[i].decode("utf-8", errors="strict")
        paths.add(normalize_repo_path(path))
        i += 1
    return paths


def enforce_allowed_paths(actual: set[str], allowed: set[str]) -> None:
    unexpected = sorted(actual - allowed)
    if unexpected:
        raise LifecycleError("unexpected changed paths: " + ", ".join(unexpected))
    if not actual:
        raise LifecycleError("no repository changes found")


def regenerate_manifest_from_index(repo: Path, manifest_path: str) -> int:
    tracked = [
        item.decode("utf-8")
        for item in _bytes(["git", "ls-files", "-z"], cwd=repo).split(b"\0")
        if item
    ]
    lines = []
    for path in tracked:
        if path == manifest_path:
            continue
        digest = hashlib.sha256(_git_blob(repo, ":" + path)).hexdigest()
        lines.append(f"{digest}  {path}")
    target = repo / manifest_path
    target.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return len(lines)


def verify_manifest_ref(repo: Path, ref: str, manifest_path: str) -> int:
    manifest = _git_blob(repo, f"{ref}:{manifest_path}").decode("ascii")
    rows = []
    for number, line in enumerate(manifest.splitlines(), 1):
        if not line.strip():
            continue
        if "  " not in line:
            raise LifecycleError(f"malformed manifest line {number}")
        digest, path = line.split("  ", 1)
        actual = hashlib.sha256(_git_blob(repo, f"{ref}:{path}")).hexdigest()
        if digest.lower() != actual:
            raise LifecycleError(f"manifest mismatch at {ref}:{path}")
        rows.append(path)
    return len(rows)


def verify_manifest_index(repo: Path, manifest_path: str) -> int:
    manifest = (repo / manifest_path).read_text(encoding="ascii")
    rows = []
    for number, line in enumerate(manifest.splitlines(), 1):
        if not line.strip():
            continue
        if "  " not in line:
            raise LifecycleError(f"malformed index manifest line {number}")
        digest, path = line.split("  ", 1)
        actual = hashlib.sha256(_git_blob(repo, ":" + path)).hexdigest()
        if digest.lower() != actual:
            raise LifecycleError(f"index manifest mismatch: {path}")
        rows.append(path)
    return len(rows)


class Journal:
    def __init__(self, path: Path, fingerprint: str) -> None:
        self.path = path
        self.fingerprint = fingerprint
        self.data: dict[str, Any] = {"contract_fingerprint": fingerprint, "steps": {}}
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if loaded.get("contract_fingerprint") != fingerprint:
                raise LifecycleError("journal belongs to a different publication contract")
            if not isinstance(loaded.get("steps"), dict):
                raise LifecycleError("journal steps are malformed")
            self.data = loaded

    def done(self, name: str) -> bool:
        return bool(self.data["steps"].get(name, {}).get("done"))

    def get(self, name: str, key: str, default: Any = None) -> Any:
        return self.data["steps"].get(name, {}).get(key, default)

    def mark(self, name: str, **values: Any) -> None:
        self.data["steps"][name] = {"done": True, **values}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(
            json.dumps(self.data, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temp, self.path)


def verify_immutable_tags(repo: Path, tags: dict[str, str]) -> None:
    for tag, expected in tags.items():
        actual = _text(["git", "rev-list", "-n", "1", tag], cwd=repo)
        if actual != expected:
            raise LifecycleError(f"immutable tag moved: {tag} {actual} != {expected}")
        print(f"IMMUTABLE_TAG=PASS {tag} {actual}")


def _release_asset_digest(repo: Path, repository: str, tag: str, name: str) -> str | None:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases/tags/{tag}"],
        cwd=str(repo),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        return None
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return None
    for asset in data.get("assets", []):
        if asset.get("name") == name:
            return asset.get("digest")
    return None


def verify_immutable_assets(repo: Path, repository: str, assets: list[dict[str, str]]) -> None:
    for item in assets:
        digest = _release_asset_digest(repo, repository, item["tag"], item["name"])
        if digest is None:
            raise LifecycleError(
                f"release asset digest unavailable: {item['tag']} / {item['name']}"
            )
        expected = "sha256:" + item["sha256"]
        if digest.lower() != expected:
            raise LifecycleError(
                f"immutable release asset changed: {item['name']} {digest} != {expected}"
            )
        print(f"IMMUTABLE_RELEASE_ASSET=PASS {item['tag']} {item['name']} {digest}")


def preflight(repo: Path, contract: dict[str, Any]) -> None:
    if not (repo / ".git").exists():
        raise LifecycleError("current directory is not a Git repository")

    origin = _text(["git", "remote", "get-url", "origin"], cwd=repo)
    if not _origin_matches_repository(origin, contract["repository"]):
        raise LifecycleError(f"origin does not match {contract['repository']}: {origin}")

    branch = _text(["git", "branch", "--show-current"], cwd=repo)
    if branch != contract["working_branch"]:
        raise LifecycleError(
            f"wrong branch: {branch!r}; expected {contract['working_branch']!r}"
        )

    _run(["git", "fetch", "origin", contract["base_branch"], "--tags"], cwd=repo)
    remote_base = _text(
        ["git", "rev-parse", f"origin/{contract['base_branch']}"], cwd=repo
    )
    if remote_base != contract["base_sha"]:
        raise LifecycleError(
            f"base branch moved: {remote_base} != {contract['base_sha']}"
        )

    merge_base = _text(["git", "merge-base", "HEAD", contract["base_sha"]], cwd=repo)
    if merge_base != contract["base_sha"]:
        raise LifecycleError("working branch does not descend from the exact base SHA")

    verify_immutable_tags(repo, contract["immutable_tags"])
    verify_immutable_assets(repo, contract["repository"], contract["immutable_release_assets"])

    changed = current_changed_paths(repo)
    enforce_allowed_paths(changed, set(contract["allowed_paths"]))
    print("PREFLIGHT_CHANGED_PATH_BOUNDARY=PASS " + str(len(changed)))


def stage_and_validate(repo: Path, contract: dict[str, Any]) -> tuple[str, int]:
    manifest = contract["manifest"]["path"]
    non_manifest = [p for p in contract["allowed_paths"] if p != manifest]
    if non_manifest:
        _run(["git", "add", "--", *non_manifest], cwd=repo)

    if contract["manifest"]["regenerate"]:
        count = regenerate_manifest_from_index(repo, manifest)
        _run(["git", "add", "--", manifest], cwd=repo)
    else:
        _run(["git", "add", "--", manifest], cwd=repo)
        count = verify_manifest_index(repo, manifest)

    staged = set(
        line for line in _text(["git", "diff", "--cached", "--name-only"], cwd=repo).splitlines()
        if line
    )
    expected = set(contract["allowed_paths"])
    if staged != expected:
        raise LifecycleError(
            "staged path boundary mismatch; expected="
            + repr(sorted(expected))
            + " actual="
            + repr(sorted(staged))
        )

    _run(["git", "diff", "--cached", "--check"], cwd=repo)
    verify_manifest_index(repo, manifest)

    tree = _text(["git", "write-tree"], cwd=repo)
    print(f"STAGED_PATH_BOUNDARY=PASS {len(staged)}/{len(expected)}")
    print(f"STAGED_MANIFEST_VERIFY=PASS {count}/{count}")
    print("STAGED_TREE=" + tree)
    return tree, count


def run_local_checks(repo: Path, contract: dict[str, Any]) -> None:
    python = sys.executable
    for command in contract["local_checks"]:
        argv = [python if item == "{python}" else item for item in command]
        _run(argv, cwd=repo)
    print(f"LOCAL_CHECKS=PASS {len(contract['local_checks'])}/{len(contract['local_checks'])}")


def ensure_commit(repo: Path, contract: dict[str, Any], journal: Journal) -> str:
    if journal.done("commit"):
        commit = journal.get("commit", "sha")
        if not isinstance(commit, str) or not HEX40.fullmatch(commit):
            raise LifecycleError("journaled commit SHA is invalid")
        if _text(["git", "rev-parse", "HEAD"], cwd=repo) != commit:
            raise LifecycleError("repository HEAD no longer matches journaled commit")
        print("RESUME_COMMIT=PASS " + commit)
        return commit

    _run(["git", "commit", "-m", contract["commit_message"]], cwd=repo)
    commit = _text(["git", "rev-parse", "HEAD"], cwd=repo)
    journal.mark("commit", sha=commit)
    print("PUBLICATION_COMMIT=" + commit)
    return commit


def ensure_push(repo: Path, contract: dict[str, Any], journal: Journal, commit: str) -> None:
    remote_ref = f"refs/heads/{contract['working_branch']}"
    remote_sha = ""
    proc = subprocess.run(
        ["git", "ls-remote", "--heads", "origin", remote_ref],
        cwd=str(repo),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        remote_sha = proc.stdout.split()[0]

    if remote_sha == commit:
        journal.mark("push", sha=commit)
        print("RESUME_PUSH=PASS " + commit)
        return

    _run(["git", "push", "-u", "origin", contract["working_branch"]], cwd=repo)
    remote_sha = _text(["git", "ls-remote", "--heads", "origin", remote_ref], cwd=repo).split()[0]
    if remote_sha != commit:
        raise LifecycleError("remote branch does not equal exact publication commit")
    journal.mark("push", sha=commit)
    print("PUSH=PASS " + commit)


def ensure_pr(repo: Path, contract: dict[str, Any], journal: Journal, commit: str) -> str:
    existing = subprocess.run(
        [
            "gh", "pr", "list",
            "--repo", contract["repository"],
            "--head", contract["working_branch"],
            "--state", "all",
            "--limit", "10",
            "--json", "number,state,headRefOid,url",
        ],
        cwd=str(repo),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if existing.returncode:
        raise LifecycleError("cannot query pull requests: " + existing.stderr.strip())
    rows = json.loads(existing.stdout or "[]")
    candidates = [row for row in rows if row.get("headRefOid") == commit]
    if len(candidates) > 1:
        raise LifecycleError("multiple PRs exist for the exact publication commit")
    if candidates:
        pr = candidates[0]
        number = str(pr["number"])
        journal.mark("pr", number=number, url=pr.get("url"), head=commit)
        print(f"RESUME_PR=PASS #{number} {pr.get('url','')}")
        return number

    url = _text(
        [
            "gh", "pr", "create",
            "--repo", contract["repository"],
            "--base", contract["base_branch"],
            "--head", contract["working_branch"],
            "--title", contract["pr_title"],
            "--body", contract["pr_body"],
        ],
        cwd=repo,
    )
    pr = json.loads(
        _text(
            [
                "gh", "pr", "view", contract["working_branch"],
                "--repo", contract["repository"],
                "--json", "number,state,headRefOid,url",
            ],
            cwd=repo,
        )
    )
    if pr.get("state") != "OPEN" or pr.get("headRefOid") != commit:
        raise LifecycleError("new PR does not bind the exact publication commit")
    number = str(pr["number"])
    journal.mark("pr", number=number, url=pr.get("url", url), head=commit)
    print(f"PR_CREATED=PASS #{number} {pr.get('url',url)}")
    return number


def wait_ci(repo: Path, contract: dict[str, Any], journal: Journal, pr: str, commit: str) -> None:
    if journal.done("ci") and journal.get("ci", "sha") == commit:
        print("RESUME_CI=PASS " + commit)
        return

    run_id = None
    for attempt in range(36):
        proc = subprocess.run(
            [
                "gh", "run", "list",
                "--repo", contract["repository"],
                "--commit", commit,
                "--event", "pull_request",
                "--limit", "1",
                "--json", "databaseId,headSha,status,conclusion",
            ],
            cwd=str(repo),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            rows = json.loads(proc.stdout or "[]") if proc.returncode == 0 else []
        except Exception:
            rows = []
        if rows and rows[0].get("headSha") == commit:
            run_id = str(rows[0]["databaseId"])
            break
        print(f"[WAIT] exact-head workflow {attempt+1}/36")
        time.sleep(5)

    if not run_id:
        raise LifecycleError("exact-head pull_request workflow was not found")

    print("PUBLIC_CI_RUN_ID=" + run_id)
    watched = _run(
        ["gh", "run", "watch", run_id, "--repo", contract["repository"], "--exit-status"],
        cwd=repo,
        check=False,
    )
    if watched.returncode:
        raise LifecycleError("exact-head public CI is not green")

    checks = json.loads(
        _text(
            [
                "gh", "pr", "checks", pr,
                "--repo", contract["repository"],
                "--json", "name,state,bucket,link",
            ],
            cwd=repo,
        )
    )
    if len(checks) != contract["ci_check_count"]:
        raise LifecycleError(
            f"unexpected CI check count: {len(checks)} != {contract['ci_check_count']}"
        )
    failed = [item for item in checks if str(item.get("bucket", "")).lower() != "pass"]
    if failed:
        raise LifecycleError("non-passing PR checks: " + json.dumps(failed))
    journal.mark("ci", sha=commit, run_id=run_id, check_count=len(checks))
    print(f"PUBLIC_CI=PASS {len(checks)}/{len(checks)}")


def merge_exact_head(
    repo: Path,
    contract: dict[str, Any],
    journal: Journal,
    pr: str,
    commit: str,
) -> str:
    if journal.done("merge"):
        merge_sha = journal.get("merge", "sha")
        info = json.loads(
            _text(
                ["gh", "pr", "view", pr, "--repo", contract["repository"], "--json", "state,mergeCommit"],
                cwd=repo,
            )
        )
        actual = (info.get("mergeCommit") or {}).get("oid")
        if info.get("state") != "MERGED" or actual != merge_sha:
            raise LifecycleError("journaled merge cannot be re-proven")
        print("RESUME_MERGE=PASS " + merge_sha)
        return merge_sha

    _run(["git", "fetch", "origin", contract["base_branch"]], cwd=repo)
    remote_base = _text(["git", "rev-parse", f"origin/{contract['base_branch']}"], cwd=repo)
    if remote_base != contract["base_sha"]:
        raise LifecycleError("base branch moved before merge; refusing automatic merge")

    info = json.loads(
        _text(
            [
                "gh", "pr", "view", pr,
                "--repo", contract["repository"],
                "--json", "state,headRefOid,mergeable,mergeStateStatus",
            ],
            cwd=repo,
        )
    )
    if info.get("state") != "OPEN":
        raise LifecycleError("PR is no longer open before merge")
    if info.get("headRefOid") != commit:
        raise LifecycleError("PR head changed before merge")
    if info.get("mergeable") != "MERGEABLE":
        raise LifecycleError("PR is not mergeable")
    if info.get("mergeStateStatus") in {"DIRTY", "BLOCKED"}:
        raise LifecycleError(f"unsafe merge state: {info.get('mergeStateStatus')}")

    args = [
        "gh", "pr", "merge", pr,
        "--repo", contract["repository"],
        "--squash",
        "--match-head-commit", commit,
    ]
    if contract["delete_branch"]:
        args.append("--delete-branch")
    _run(args, cwd=repo)

    merged = json.loads(
        _text(
            ["gh", "pr", "view", pr, "--repo", contract["repository"], "--json", "state,mergeCommit"],
            cwd=repo,
        )
    )
    merge_sha = (merged.get("mergeCommit") or {}).get("oid")
    if merged.get("state") != "MERGED" or not isinstance(merge_sha, str):
        raise LifecycleError("merge result cannot be verified")
    journal.mark("merge", sha=merge_sha, head=commit)
    print("MERGE=PASS " + merge_sha)
    return merge_sha


def postverify(
    repo: Path,
    contract: dict[str, Any],
    merge_sha: str,
) -> None:
    _run(["git", "fetch", "origin", contract["base_branch"], "--tags"], cwd=repo)
    remote_main = _text(["git", "rev-parse", f"origin/{contract['base_branch']}"], cwd=repo)
    if remote_main != merge_sha:
        raise LifecycleError("base branch does not equal exact merge SHA")

    verify_immutable_tags(repo, contract["immutable_tags"])
    verify_immutable_assets(repo, contract["repository"], contract["immutable_release_assets"])

    manifest_count = verify_manifest_ref(repo, f"origin/{contract['base_branch']}", contract["manifest"]["path"])
    changed = set(
        line
        for line in _text(
            ["git", "diff", "--name-only", contract["base_sha"] + ".." + f"origin/{contract['base_branch']}"],
            cwd=repo,
        ).splitlines()
        if line
    )
    expected = set(contract["allowed_paths"])
    if changed != expected:
        raise LifecycleError(
            "post-merge path boundary mismatch; expected="
            + repr(sorted(expected))
            + " actual="
            + repr(sorted(changed))
        )
    print(f"POST_MERGE_PATH_BOUNDARY=PASS {len(changed)}/{len(expected)}")
    print(f"POST_MERGE_MANIFEST_VERIFY=PASS {manifest_count}/{manifest_count}")
    print("POST_MERGE_MAIN=PASS " + merge_sha)


def dry_run(repo: Path, contract: dict[str, Any]) -> None:
    preflight(repo, contract)
    changed = current_changed_paths(repo)
    print("DRY_RUN=PASS")
    print("WOULD_STAGE=" + ",".join(sorted(changed)))
    print("WOULD_RUN_LOCAL_CHECKS=" + str(len(contract["local_checks"])))
    print("WOULD_PUSH_BRANCH=" + contract["working_branch"])
    print("WOULD_REQUIRE_CI_CHECKS=" + str(contract["ci_check_count"]))
    print("WOULD_EXACT_HEAD_SQUASH_MERGE=YES")


def apply(repo: Path, contract: dict[str, Any], journal_path: Path) -> None:
    _run(["gh", "auth", "status"], cwd=repo, capture=True)
    fingerprint = contract_fingerprint(contract)
    journal = Journal(journal_path, fingerprint)
    print("CONTRACT_FINGERPRINT=" + fingerprint)
    print("JOURNAL=" + str(journal_path))

    preflight(repo, contract)

    if not journal.done("stage"):
        tree, count = stage_and_validate(repo, contract)
        journal.mark("stage", tree=tree, manifest_count=count)
    else:
        tree = journal.get("stage", "tree")
        current_tree = _text(["git", "write-tree"], cwd=repo)
        if current_tree != tree:
            raise LifecycleError("staged tree differs from journaled staged tree")
        print("RESUME_STAGE=PASS " + str(tree))

    if not journal.done("local_checks"):
        run_local_checks(repo, contract)
        journal.mark("local_checks")
    else:
        print("RESUME_LOCAL_CHECKS=PASS")

    commit = ensure_commit(repo, contract, journal)
    ensure_push(repo, contract, journal, commit)
    pr = ensure_pr(repo, contract, journal, commit)
    wait_ci(repo, contract, journal, pr, commit)
    merge_sha = merge_exact_head(repo, contract, journal, pr, commit)
    postverify(repo, contract, merge_sha)
    journal.mark("postverify", merge_sha=merge_sha)

    print("=" * 72)
    print("PUBLICATION_LIFECYCLE=SUCCESS")
    print("IDEMPOTENT_RESUME=ENABLED")
    print("EXACT_HEAD_MERGE=ENFORCED")
    print("APPLICATION_CODE_MUTATION=CALLER_SCOPED_ONLY")
    print("IMMUTABLE_RELEASE_GUARDS=PASS")
    print("PUBLICATION_LIFECYCLE=CLOSED")
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail-closed, resumable GitHub publication lifecycle for VulnFlow."
    )
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true", help="Allow Git/GitHub mutations.")
    parser.add_argument("--journal", type=Path, default=None)
    parser.add_argument("--print-fingerprint", action="store_true")
    args = parser.parse_args()

    contract = load_contract(args.contract.resolve())
    fingerprint = contract_fingerprint(contract)
    if args.print_fingerprint:
        print(fingerprint)
        return

    repo = args.repo.resolve()
    if args.apply:
        journal = args.journal
        if journal is None:
            journal = DEFAULT_JOURNAL_DIR / (fingerprint + ".json")
        apply(repo, contract, journal.resolve())
    else:
        dry_run(repo, contract)


if __name__ == "__main__":
    try:
        main()
    except LifecycleError as exc:
        print("[FAIL] " + str(exc), file=sys.stderr)
        raise SystemExit(2)
