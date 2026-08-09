from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _assignment_string(path: Path, name: str) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: list[str] = []
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        if node.targets[0].id != name:
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            values.append(node.value.value)
    if len(values) != 1:
        raise RuntimeError(
            f"{path.relative_to(ROOT)} must define exactly one string {name}; "
            f"found {len(values)}"
        )
    return values[0]


def _single_regex(path: Path, pattern: str, label: str) -> str:
    matches = re.findall(
        pattern,
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise RuntimeError(
            f"{path.relative_to(ROOT)} must contain exactly one {label}; "
            f"found {len(matches)}"
        )
    return str(matches[0])


def main() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    app_version = _assignment_string(
        ROOT / "app/core/schema_versions.py",
        "CURRENT_APP_VERSION",
    )
    citation_version = _single_regex(
        ROOT / "CITATION.cff",
        r'^version:\s*"([^"]+)"\s*$',
        "CITATION version",
    )
    docker_version = _single_regex(
        ROOT / "docker-compose.yml",
        r'vulnflow:([0-9]+\.[0-9]+\.[0-9]+)',
        "default Docker image version",
    )

    runtime_header = (
        ROOT / "requirements.lock"
    ).read_text(encoding="utf-8").splitlines()[0]
    development_header = (
        ROOT / "requirements-dev.lock"
    ).read_text(encoding="utf-8").splitlines()[0]

    runtime_manifest = json.loads((ROOT / "app/resources/runtime_dependency_lock.json").read_text(encoding="utf-8"))
    bom = json.loads((ROOT / "bom.cdx.json").read_text(encoding="utf-8"))
    component = (bom.get("metadata") or {}).get("component") or {}
    dependencies = bom.get("dependencies") or []
    root_prefix = "pkg:generic/vulnflow@"
    root_entries = [
        item
        for item in dependencies
        if str(item.get("ref") or "").startswith(root_prefix)
    ]
    expected_ref = f"{root_prefix}{version}"
    dependency_root_ref = (
        str(root_entries[0].get("ref") or "")
        if len(root_entries) == 1
        else ""
    )

    checks = [
        ("version_nonempty", bool(version)),
        ("pyproject_version", str(pyproject["project"]["version"]) == version),
        ("application_version", app_version == version),
        ("citation_version", citation_version == version),
        ("docker_image_version", docker_version == version),
        ("runtime_lock_header", runtime_header.startswith(f"# VulnFlow {version}")),
        ("runtime_dependency_manifest_version", str(runtime_manifest.get("application_version") or "") == version),
        (
            "development_lock_header",
            development_header.startswith(f"# VulnFlow {version}"),
        ),
        ("sbom_metadata_version", str(component.get("version") or "") == version),
        (
            "sbom_metadata_bom_ref",
            str(component.get("bom-ref") or "") == expected_ref,
        ),
        ("sbom_dependency_root_count", len(root_entries) == 1),
        ("sbom_dependency_root_ref", dependency_root_ref == expected_ref),
    ]

    failed = [name for name, passed in checks if not passed]
    print(f"VulnFlow {version} release metadata consistency")
    print()
    for name, passed in checks:
        print(f"{name}: {'PASS' if passed else 'FAIL'}")
    print()
    print(f"passed: {len(checks) - len(failed)}/{len(checks)}")
    if failed:
        raise SystemExit(
            "release metadata consistency failed: " + ", ".join(failed)
        )


if __name__ == "__main__":
    main()
