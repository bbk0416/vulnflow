from __future__ import annotations

"""Fail closed when release-facing operational documentation drifts from code.

The gate intentionally derives values from executable/source-of-truth files rather
than duplicating release numbers in another configuration file.  It covers the
small set of facts whose drift can mislead operators: public regression counts,
version/schema, database layout, and browser-login rate-limit semantics.
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _single_assignment_literal(path: Path, name: str):
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = []
    for node in ast.walk(module):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value_node = node.value
        try:
            values.append(ast.literal_eval(value_node))
        except (ValueError, TypeError):
            continue
    if len(values) != 1:
        raise RuntimeError(f"{path.relative_to(ROOT)} must define one literal {name}; found {len(values)}")
    return values[0]


def _settings_default(settings_text: str, env_name: str) -> str:
    # Match the reviewed getenv default contract. Structural changes intentionally
    # fail this gate so the documentation contract is reviewed with the code change.
    matches = re.findall(
        rf'os\.getenv\("{re.escape(env_name)}",\s*"([^"]+)"\)',
        settings_text,
    )
    if len(matches) != 1:
        raise RuntimeError(f"app/core/settings.py must expose one literal default for {env_name}; found {len(matches)}")
    return matches[0]


def _function_return_list_length(path: Path, function_name: str) -> int:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    matches = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == function_name]
    if len(matches) != 1:
        raise RuntimeError(f"{path.relative_to(ROOT)} must define one {function_name} function; found {len(matches)}")
    returns = [node for node in ast.walk(matches[0]) if isinstance(node, ast.Return) and isinstance(node.value, ast.List)]
    if len(returns) != 1:
        raise RuntimeError(f"{path.relative_to(ROOT)}:{function_name} must return one literal list; found {len(returns)}")
    return len(returns[0].value.elts)


def _manifest_entry_count(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _contains(path: Path, needle: str) -> bool:
    return needle in path.read_text(encoding="utf-8")


def _absent(path: Path, needle: str) -> bool:
    return needle not in path.read_text(encoding="utf-8")


def consistency_issues(root: Path = ROOT) -> list[str]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    schema = int(_single_assignment_literal(root / "app/core/schema_versions.py", "CURRENT_SCHEMA_VERSION"))
    group_counts = tuple(int(item) for item in _single_assignment_literal(root / "scripts/run_public_tests.py", "expected_counts"))
    public_total = sum(group_counts)
    group_text = " + ".join(str(item) for item in group_counts)
    manifest_count = _manifest_entry_count(root / "SHA256SUMS.txt")
    submission_count = _function_return_list_length(root / "scripts/submission_readiness_smoke.py", "_public_checks")

    settings = (root / "app/core/settings.py").read_text(encoding="utf-8")
    auth_window = int(_settings_default(settings, "VULNFLOW_AUTH_RATE_WINDOW_SECONDS"))
    auth_user_client = int(_settings_default(settings, "VULNFLOW_AUTH_RATE_USERNAME_CLIENT_ATTEMPTS"))
    auth_client = int(_settings_default(settings, "VULNFLOW_AUTH_RATE_CLIENT_ATTEMPTS"))

    readme = root / "README.md"
    scope = root / "PUBLIC_SCOPE.md"
    verification = root / "PUBLIC_VERIFICATION.txt"
    rbac = root / "docs/12_RBAC_APPROVALS.md"
    operations = root / "docs/05_OPERATIONS_GUIDE.md"
    env_example = root / ".env.example"
    workflow = root / ".github/workflows/public-ci.yml"
    release_notes = root / f"RELEASE_NOTES_{version}.md"

    checks = [
        ("readme_version", _contains(readme, f"Core {version}")),
        ("readme_public_test_count", _contains(readme, f"**{public_total}개**")),
        ("public_scope_test_count", _contains(scope, f"{public_total}개 수집형 핵심 회귀시험")),
        ("public_scope_schema", _contains(scope, f"schema {schema}")),
        (
            "public_verification_test_contract",
            _contains(
                verification,
                f"public regression suite: {public_total}/{public_total} PASS across seven bounded groups ({group_text})",
            ),
        ),
        ("public_verification_version", _contains(verification, f"VulnFlow {version} public verification summary")),
        ("current_release_notes_exists", release_notes.is_file()),
        ("readme_current_release_notes", _contains(readme, f"RELEASE_NOTES_{version}.md")),
        ("public_scope_current_version", _contains(scope, f"## {version} ")),
        ("public_verification_release_notes", _contains(verification, f"release notes: RELEASE_NOTES_{version}.md")),
        (
            "public_verification_submission_count",
            _contains(verification, f"public submission readiness: {submission_count}/{submission_count} PASS"),
        ),
        (
            "public_verification_manifest_count",
            _contains(verification, f"public manifest: {manifest_count}/{manifest_count} PASS"),
        ),
        ("rbac_control_db", _contains(rbac, "--db ./data/control.db create --username admin --role admin")),
        ("rbac_sliding_window", _contains(rbac, f"기본 {auth_window}초 sliding window")),
        ("rbac_username_client_limit", _contains(rbac, f"username+client 기준 {auth_user_client}회")),
        ("rbac_client_limit", _contains(rbac, f"client 전체 기준 {auth_client}회")),
        ("rbac_no_global_lockout", _contains(rbac, "계정 전역 잠금은 사용하지 않습니다")),
        ("rbac_stale_15m_lockout_absent", _absent(rbac, "15분 잠금")),
        ("operations_control_db", _contains(operations, "data/control.db")),
        ("operations_project_db", _contains(operations, "data/projects/default/vulnflow.db")),
        ("env_first_admin_control_db", _contains(env_example, "--db ./data/control.db create --username admin --role admin")),
        ("env_auth_window", _contains(env_example, f"VULNFLOW_AUTH_RATE_WINDOW_SECONDS={auth_window}")),
        ("env_auth_username_client", _contains(env_example, f"VULNFLOW_AUTH_RATE_USERNAME_CLIENT_ATTEMPTS={auth_user_client}")),
        ("env_auth_client", _contains(env_example, f"VULNFLOW_AUTH_RATE_CLIENT_ATTEMPTS={auth_client}")),
        ("ci_documentation_gate", _contains(workflow, "python scripts/documentation_consistency_smoke.py")),
    ]
    return [name for name, passed in checks if not passed]


def main() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    group_counts = tuple(int(item) for item in _single_assignment_literal(ROOT / "scripts/run_public_tests.py", "expected_counts"))
    issues = consistency_issues(ROOT)
    print(f"VulnFlow {version} documentation consistency")
    print(f"public regression contract: {' + '.join(map(str, group_counts))} = {sum(group_counts)}")
    if issues:
        for issue in issues:
            print(f"FAIL: {issue}")
        raise SystemExit(1)
    print("documentation consistency: PASS")


if __name__ == "__main__":
    main()
