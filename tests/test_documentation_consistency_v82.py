from __future__ import annotations

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
    path.write_text(path.read_text(encoding="utf-8").replace("**706개**", "**705개**"), encoding="utf-8")
    assert "readme_public_test_count" in consistency_issues(root)

    verification_root = _copy_contract_tree(tmp_path / "verification")
    verification = verification_root / "PUBLIC_VERIFICATION.txt"
    verification.write_text(
        verification.read_text(encoding="utf-8").replace(
            "public manifest: 676/676 PASS",
            "public manifest: 673/673 PASS",
        ),
        encoding="utf-8",
    )
    assert "public_verification_manifest_count" in consistency_issues(verification_root)

    release_root = _copy_contract_tree(tmp_path / "release")
    verification = release_root / "PUBLIC_VERIFICATION.txt"
    verification.write_text(
        verification.read_text(encoding="utf-8").replace(
            "release notes: RELEASE_NOTES_72.0.83.md",
            "release notes: RELEASE_NOTES_72.0.82.md",
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
