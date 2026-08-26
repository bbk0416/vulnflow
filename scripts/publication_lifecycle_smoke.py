from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve()
TARGET = HERE.with_name("publication_lifecycle.py")
spec = importlib.util.spec_from_file_location("publication_lifecycle", TARGET)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def contract():
    return {
        "schema": 1,
        "repository": "example/project",
        "base_branch": "main",
        "base_sha": "a" * 40,
        "working_branch": "maintenance/example",
        "commit_message": "test: example",
        "pr_title": "test: example",
        "pr_body": "example",
        "allowed_paths": ["a.txt", "SHA256SUMS.txt"],
        "manifest": {"path": "SHA256SUMS.txt", "regenerate": True},
        "ci_check_count": 8,
        "local_checks": [["{python}", "-c", "print('ok')"]],
        "immutable_tags": {"v1": "b" * 40},
        "immutable_release_assets": [
            {"tag": "v1", "name": "artifact.zip", "sha256": "c" * 64}
        ],
        "merge_method": "squash",
        "delete_branch": True,
    }


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def main():
    c = mod.validate_contract(contract())
    assert c["allowed_paths"] == ["SHA256SUMS.txt", "a.txt"]
    fp1 = mod.contract_fingerprint(c)
    fp2 = mod.contract_fingerprint(mod.validate_contract(contract()))
    assert fp1 == fp2 and len(fp1) == 64

    bad = contract()
    bad["allowed_paths"] = ["../escape", "SHA256SUMS.txt"]
    try:
        mod.validate_contract(bad)
    except mod.LifecycleError:
        pass
    else:
        raise AssertionError("path traversal contract was accepted")

    bad = contract()
    bad["allowed_paths"] = ["a.txt", "a.txt", "SHA256SUMS.txt"]
    try:
        mod.validate_contract(bad)
    except mod.LifecycleError:
        pass
    else:
        raise AssertionError("duplicate allowed path was accepted")

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        git(repo, "init")
        git(repo, "config", "user.email", "smoke@example.invalid")
        git(repo, "config", "user.name", "Smoke")
        (repo / "a.txt").write_text("one\n", encoding="utf-8", newline="\n")
        (repo / "b.txt").write_text("two\n", encoding="utf-8", newline="\n")
        (repo / "SHA256SUMS.txt").write_text("", encoding="ascii")
        git(repo, "add", "a.txt", "b.txt", "SHA256SUMS.txt")

        count = mod.regenerate_manifest_from_index(repo, "SHA256SUMS.txt")
        assert count == 2
        git(repo, "add", "SHA256SUMS.txt")
        assert mod.verify_manifest_index(repo, "SHA256SUMS.txt") == 2

        mod.enforce_allowed_paths({"a.txt"}, {"a.txt", "SHA256SUMS.txt"})
        try:
            mod.enforce_allowed_paths({"a.txt", "evil.txt"}, {"a.txt", "SHA256SUMS.txt"})
        except mod.LifecycleError:
            pass
        else:
            raise AssertionError("unexpected path boundary was accepted")

        journal_path = repo / "journal.json"
        journal = mod.Journal(journal_path, fp1)
        journal.mark("stage", tree="abc")
        journal2 = mod.Journal(journal_path, fp1)
        assert journal2.done("stage")
        assert journal2.get("stage", "tree") == "abc"
        try:
            mod.Journal(journal_path, "d" * 64)
        except mod.LifecycleError:
            pass
        else:
            raise AssertionError("foreign contract journal was accepted")

    print("contract_validation: PASS")
    print("contract_fingerprint: PASS")
    print("path_boundary: PASS")
    print("manifest_regeneration: PASS")
    print("journal_resume_binding: PASS")
    print("publication_lifecycle_smoke: PASS")


if __name__ == "__main__":
    main()
