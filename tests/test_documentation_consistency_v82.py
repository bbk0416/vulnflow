from __future__ import annotations

import re
import shutil
from pathlib import Path

from scripts.documentation_consistency_smoke import consistency_issues

ROOT = Path(__file__).resolve().parents[1]


def _copy_contract_tree(tmp_path: Path) -> Path:
    rels = [
        "VERSION",
        "README.md",
        "PUBLIC_SCOPE.md",
        "PUBLIC_VERIFICATION.txt",
        ".env.example",
        "app/core/schema_versions.py",
        "app/core/settings.py",
        "scripts/run_public_tests.py",
        "scripts/submission_readiness_smoke.py",
        "SHA256SUMS.txt",
        "docs/12_RBAC_APPROVALS.md",
        "docs/05_OPERATIONS_GUIDE.md",
        "docs/01_PROBLEM_AND_SCOPE.md",
        "docs/95_REPOSITORY_MAINTENANCE_POLICY.md",
        "tests/e2e/test_vm_workflows.py",
        ".github/workflows/public-ci.yml",
        f"RELEASE_NOTES_{(ROOT / 'VERSION').read_text(encoding='utf-8').strip()}.md",
    ]
    for rel in rels:
        source = ROOT / rel
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return tmp_path


def test_current_documentation_contract_passes() -> None:
    assert consistency_issues(ROOT) == []


def test_stale_public_regression_count_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / "README.md"
    readme_text = path.read_text(encoding="utf-8")
    count_matches = list(re.finditer(r"\*\*(\d+)개\*\*", readme_text))
    assert len(count_matches) == 1
    count_match = count_matches[0]
    current_public_test_count = int(count_match.group(1))
    stale_public_test_count = max(0, current_public_test_count - 1)
    path.write_text(
        readme_text[: count_match.start(1)]
        + str(stale_public_test_count)
        + readme_text[count_match.end(1) :],
        encoding="utf-8",
    )
    assert "readme_public_test_count" in consistency_issues(root)

    verification_root = _copy_contract_tree(tmp_path / "verification")
    verification = verification_root / "PUBLIC_VERIFICATION.txt"
    verification_text = verification.read_text(encoding="utf-8")
    manifest_match = re.search(
        r"public manifest: (\d+)/(\d+) PASS",
        verification_text,
    )
    assert manifest_match is not None
    assert manifest_match.group(1) == manifest_match.group(2)
    current_manifest_count = int(manifest_match.group(1))
    stale_manifest_count = max(0, current_manifest_count - 1)
    verification.write_text(
        verification_text[: manifest_match.start(1)]
        + str(stale_manifest_count)
        + "/"
        + str(stale_manifest_count)
        + verification_text[manifest_match.end(2) :],
        encoding="utf-8",
    )
    assert "public_verification_manifest_count" in consistency_issues(verification_root)

    release_root = _copy_contract_tree(tmp_path / "release")
    verification = release_root / "PUBLIC_VERIFICATION.txt"
    verification.write_text(
        verification.read_text(encoding="utf-8").replace(
            "release notes: RELEASE_NOTES_72.0.104.md",
            "release notes: RELEASE_NOTES_72.0.86.md",
        ),
        encoding="utf-8",
    )
    assert "public_verification_release_notes" in consistency_issues(release_root)



def test_stale_release_identity_fails_closed(tmp_path: Path) -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    published_without_tag = _copy_contract_tree(tmp_path / "published-without-tag")
    assert "public_verification_release_state" in consistency_issues(
        published_without_tag,
        release_tag_exists=False,
    )

    candidate_root = _copy_contract_tree(tmp_path / "candidate-state")
    candidate_readme = candidate_root / "README.md"
    candidate_readme.write_text(
        candidate_readme.read_text(encoding="utf-8")
        .replace(
            "Latest public release: [`v72.0.104`](https://github.com/bbk0416/vulnflow/releases/tag/v72.0.104) at commit `52837dfdb61c151aeefb91ca66bf4edcad0ddaef`.",
            "Latest public release: [`v72.0.103`](https://github.com/bbk0416/vulnflow/releases/tag/v72.0.103) at commit `f87943c81747799134705d47fd354c79f3c24d69`.",
        )
        .replace(
            "not included in the `v72.0.104` release asset",
            "not included in the `v72.0.103` release asset",
        )
        encoding="utf-8",
    )
    candidate_verification = candidate_root / "PUBLIC_VERIFICATION.txt"
    candidate_text = candidate_verification.read_text(encoding="utf-8")
    published_start = candidate_text.index("Published release evidence:")
    boundary_start = candidate_text.index("\nRelease boundary:", published_start)
    candidate_block = """Release candidate boundary:
- annotated tag `v72.0.104` must be created only from the exact squash-merged release commit after the required checks pass
- Windows asset: `VulnFlow_Free_Public_Beta_Windows_Core_72.0.104.zip`
- the asset must be built only from exact Git HEAD blobs covered by `SHA256SUMS.txt` and must re-verify every archived manifest entry
- CodeQL `Analyze (actions)` and `Analyze (python)` must both succeed on the release commit before publication
- the official v72.0.103 predecessor tag remains protected against update/deletion; its legacy GitHub Release is not claimed natively immutable
"""
    candidate_verification.write_text(
        candidate_text[:published_start] + candidate_block + candidate_text[boundary_start:],
        encoding="utf-8",
    )
    candidate_pre_publish = consistency_issues(candidate_root, release_tag_exists=False)
    assert "public_verification_release_state" not in candidate_pre_publish
    assert "readme_release_identity_version" not in candidate_pre_publish
    assert "readme_release_identity_asset_version" not in candidate_pre_publish
    candidate_post_publish = consistency_issues(candidate_root, release_tag_exists=True)
    assert "public_verification_release_state" in candidate_post_publish

    candidate_root = _copy_contract_tree(tmp_path / "candidate-stale-readme")
    candidate_readme = candidate_root / "README.md"
    candidate_text = candidate_readme.read_text(encoding="utf-8")
    candidate_text = re.sub(
        r"Latest public release: \[`v[0-9]+\.[0-9]+\.[0-9]+`\]\(",
        "Latest public release: [`v0.0.0`](",
        candidate_text,
        count=1,
    )
    candidate_readme.write_text(candidate_text, encoding="utf-8")
    assert "readme_release_identity_version" in consistency_issues(candidate_root)

    identity_root = _copy_contract_tree(tmp_path / "identity")
    identity_readme = identity_root / "README.md"
    identity_verification = identity_root / "PUBLIC_VERIFICATION.txt"
    if "Release candidate boundary:" in identity_verification.read_text(encoding="utf-8"):
        identity_verification.write_text(
            identity_verification.read_text(encoding="utf-8").replace(
                "Release candidate boundary:",
                "Unrecognized candidate boundary:",
            ),
            encoding="utf-8",
        )
    else:
        identity_readme.write_text(
            identity_readme.read_text(encoding="utf-8")
            .replace(
                f"Latest public release: [`v{version}`](",
                "Latest public release: [`v0.0.0`](",
            )
            .replace(
                f"not included in the `v{version}` release asset",
                "not included in the `v0.0.0` release asset",
            ),
            encoding="utf-8",
        )
    identity_issues = consistency_issues(identity_root)
    assert "readme_release_identity_version" in identity_issues
    assert "readme_release_identity_asset_version" in identity_issues

    verification_root = _copy_contract_tree(tmp_path / "verification-release")
    verification = verification_root / "PUBLIC_VERIFICATION.txt"
    verification.write_text(
        verification.read_text(encoding="utf-8").replace(
            f"annotated tag `v{version}`",
            "annotated tag `v0.0.0`",
        ),
        encoding="utf-8",
    )
    assert "public_verification_published_tag" in consistency_issues(verification_root)

    windows_asset_root = _copy_contract_tree(tmp_path / "windows-asset")
    windows_verification = windows_asset_root / "PUBLIC_VERIFICATION.txt"
    windows_verification.write_text(
        windows_verification.read_text(encoding="utf-8").replace(
            f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip",
            "VulnFlow_Free_Public_Beta_Windows_Core_0.0.0.zip",
        ),
        encoding="utf-8",
    )
    assert "public_verification_windows_asset" in consistency_issues(windows_asset_root)

def test_stale_browser_e2e_count_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    readme = root / "README.md"
    readme_text = readme.read_text(encoding="utf-8")
    match = re.search(r"Chromium 브라우저 E2E (\d+)개", readme_text)
    assert match is not None
    current = int(match.group(1))
    readme.write_text(
        readme_text[: match.start(1)] + str(max(0, current - 1)) + readme_text[match.end(1) :],
        encoding="utf-8",
    )
    assert "readme_browser_e2e_count" in consistency_issues(root)

    scope_root = _copy_contract_tree(tmp_path / "scope")
    scope = scope_root / "PUBLIC_SCOPE.md"
    scope_text = scope.read_text(encoding="utf-8")
    match = re.search(r"Chromium 브라우저 E2E (\d+)개", scope_text)
    assert match is not None
    current = int(match.group(1))
    scope.write_text(
        scope_text[: match.start(1)] + str(max(0, current - 1)) + scope_text[match.end(1) :],
        encoding="utf-8",
    )
    assert "public_scope_browser_e2e_count" in consistency_issues(scope_root)


def test_stale_maintenance_public_test_count_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / "docs/95_REPOSITORY_MAINTENANCE_POLICY.md"
    policy_text = path.read_text(encoding="utf-8")
    match = re.search(r"the (\d+)-test public regression suite;", policy_text)
    assert match is not None
    current = int(match.group(1))
    path.write_text(
        policy_text[: match.start(1)] + str(max(0, current - 1)) + policy_text[match.end(1) :],
        encoding="utf-8",
    )
    assert "maintenance_public_test_count" in consistency_issues(root)


def test_stale_jira_exclusion_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / "docs/01_PROBLEM_AND_SCOPE.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "ServiceNow·GitHub·SIEM 등 현재 구현되지 않은 외부 시스템의 정식 adapter",
            "Jira·ServiceNow·GitHub·SIEM 등 외부 시스템의 정식 adapter",
        ),
        encoding="utf-8",
    )
    issues = consistency_issues(root)
    assert "problem_scope_external_adapters" in issues
    assert "problem_scope_stale_jira_exclusion_absent" in issues

def test_stale_account_lockout_language_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / "docs/12_RBAC_APPROVALS.md"
    path.write_text(path.read_text(encoding="utf-8") + "\n기본 5회 연속 실패 시 15분 잠금\n", encoding="utf-8")
    assert "rbac_stale_15m_lockout_absent" in consistency_issues(root)


def test_stale_first_admin_database_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / ".env.example"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "--db ./data/control.db create --username admin --role admin",
            "--db ./data/vulnflow.db create --username admin --role admin",
        ),
        encoding="utf-8",
    )
    assert "env_first_admin_control_db" in consistency_issues(root)


def test_missing_ci_documentation_gate_fails_closed(tmp_path: Path) -> None:
    root = _copy_contract_tree(tmp_path)
    path = root / ".github/workflows/public-ci.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace("python scripts/documentation_consistency_smoke.py", "python -c pass"),
        encoding="utf-8",
    )
    assert "ci_documentation_gate" in consistency_issues(root)

    coverage_root = _copy_contract_tree(tmp_path / "coverage")
    coverage_workflow = coverage_root / ".github/workflows/public-ci.yml"
    coverage_workflow.write_text(
        coverage_workflow.read_text(encoding="utf-8").replace(
            "python scripts/coverage_verification.py",
            "python -c pass",
        ),
        encoding="utf-8",
    )
    assert "ci_coverage_gate" in consistency_issues(coverage_root)

    coverage_name_root = _copy_contract_tree(tmp_path / "coverage-name")
    coverage_name_workflow = coverage_name_root / ".github/workflows/public-ci.yml"
    coverage_name_workflow.write_text(
        coverage_name_workflow.read_text(encoding="utf-8").replace(
            "name: coverage / Python 3.13",
            "name: coverage",
        ),
        encoding="utf-8",
    )
    assert "ci_coverage_job_name" in consistency_issues(coverage_name_root)
