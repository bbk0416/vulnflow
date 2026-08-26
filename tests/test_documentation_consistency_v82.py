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
            "release notes: RELEASE_NOTES_72.0.102.md",
            "release notes: RELEASE_NOTES_72.0.86.md",
        ),
        encoding="utf-8",
    )
    assert "public_verification_release_notes" in consistency_issues(release_root)


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
