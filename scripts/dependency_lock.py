from __future__ import annotations

"""Validate VulnFlow's exact dependency locks and installation entry points."""

import argparse
import json
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path
from typing import Iterable

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_INPUT = ROOT / "requirements.txt"
DEV_INPUT = ROOT / "requirements-dev.txt"
RUNTIME_LOCK = ROOT / "requirements.lock"
DEV_LOCK = ROOT / "requirements-dev.lock"
PYTHON_VERSION_FILE = ROOT / ".python-version"


def _lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]


def _requirements(path: Path, *, follow_includes: bool = False) -> list[Requirement]:
    result: list[Requirement] = []
    for line in _lines(path):
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r ") or line.startswith("--requirement "):
            if follow_includes:
                included = line.split(maxsplit=1)[1]
                result.extend(_requirements(path.parent / included, follow_includes=True))
            continue
        result.append(Requirement(line))
    return result


def _mapping(requirements: Iterable[Requirement]) -> dict[str, Requirement]:
    return {canonicalize_name(req.name): req for req in requirements}


def _exact_pin(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator != "==" or specs[0].version.endswith(".*"):
        return None
    return specs[0].version


def _marker_applies(req: Requirement, *, extras: Iterable[str] = ()) -> bool:
    if req.marker is None:
        return True
    environments = []
    extra_values = list(extras) or [""]
    for extra in extra_values:
        env = default_environment()
        env["extra"] = extra
        environments.append(env)
    return any(req.marker.evaluate(env) for env in environments)


def _active_lock(path: Path) -> dict[str, Requirement]:
    return {
        canonicalize_name(req.name): req
        for req in _requirements(path, follow_includes=True)
        if _marker_applies(req)
    }


def _dependency_closure(inputs: Path) -> set[str]:
    direct = _requirements(inputs)
    queue: list[tuple[str, frozenset[str]]] = [
        (canonicalize_name(req.name), frozenset(req.extras)) for req in direct
    ]
    visited: set[tuple[str, frozenset[str]]] = set()
    names: set[str] = set()
    while queue:
        name, extras = queue.pop()
        key = (name, extras)
        if key in visited:
            continue
        visited.add(key)
        names.add(name)
        try:
            requires = metadata.requires(name) or []
        except metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"installed package missing while resolving closure: {name}") from exc
        for raw in requires:
            req = Requirement(raw)
            if not _marker_applies(req, extras=extras):
                continue
            queue.append((canonicalize_name(req.name), frozenset(req.extras)))
    return names


def _version_map(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for req in _requirements(path, follow_includes=True):
        pin = _exact_pin(req)
        if pin is None:
            continue
        values[canonicalize_name(req.name)] = pin
    return values


def consistency_issues(*, check_installed: bool = False) -> list[str]:
    issues: list[str] = []
    runtime_input = _mapping(_requirements(RUNTIME_INPUT))
    dev_input = _mapping(_requirements(DEV_INPUT, follow_includes=True))
    runtime_lock = _mapping(_requirements(RUNTIME_LOCK))
    dev_lock = _mapping(_requirements(DEV_LOCK, follow_includes=True))

    for label, requirements in (("runtime lock", runtime_lock), ("development lock", dev_lock)):
        for name, req in requirements.items():
            if _exact_pin(req) is None:
                issues.append(f"{label} entry is not an exact pin: {name}: {req}")

    for label, direct, locked in (
        ("runtime", runtime_input, runtime_lock),
        ("development", dev_input, dev_lock),
    ):
        for name, req in direct.items():
            direct_pin = _exact_pin(req)
            locked_req = locked.get(name)
            locked_pin = _exact_pin(locked_req) if locked_req else None
            if locked_req is None:
                issues.append(f"{label} direct dependency missing from lock: {name}")
            elif direct_pin != locked_pin:
                issues.append(
                    f"{label} direct dependency drift: {name}: input={direct_pin!r} lock={locked_pin!r}"
                )

    runtime_versions = _version_map(RUNTIME_LOCK)
    dev_versions = _version_map(DEV_LOCK)
    for name, version in runtime_versions.items():
        if dev_versions.get(name) != version:
            issues.append(f"development lock does not preserve runtime pin: {name}=={version}")

    if check_installed:
        for label, input_path, lock_path in (
            ("runtime", RUNTIME_INPUT, RUNTIME_LOCK),
            ("development", DEV_INPUT, DEV_LOCK),
        ):
            closure = _dependency_closure(input_path)
            active_lock = _active_lock(lock_path)
            missing = sorted(closure - set(active_lock))
            if missing:
                issues.append(f"{label} dependency closure missing from lock: {', '.join(missing)}")
            for name, req in active_lock.items():
                pin = _exact_pin(req)
                try:
                    installed = metadata.version(name)
                except metadata.PackageNotFoundError:
                    issues.append(f"active locked package is not installed: {name}=={pin}")
                    continue
                if installed != pin:
                    issues.append(
                        f"installed package drift: {name}: installed={installed!r} lock={pin!r}"
                    )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "COPY requirements.lock ." not in dockerfile:
        issues.append("Dockerfile does not copy requirements.lock")
    if not re.search(r"pip install .*requirements\.lock", dockerfile):
        issues.append("Dockerfile does not install requirements.lock")

    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    if "requirements-dev.lock" not in workflow:
        issues.append("CI does not install requirements-dev.lock")

    python_minor = PYTHON_VERSION_FILE.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"3\.\d+", python_minor):
        issues.append(".python-version must pin Python major.minor")
    if f"python-version: '{python_minor}'" not in workflow:
        issues.append("CI Python version does not match .python-version")
    if f"FROM python:{python_minor}-slim" not in dockerfile:
        issues.append("Docker Python version does not match .python-version")

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project") or {}
    if str(project.get("version") or "") != (ROOT / "VERSION").read_text(encoding="utf-8").strip():
        issues.append("pyproject project.version does not match VERSION")
    pyproject_runtime = _mapping(Requirement(item) for item in project.get("dependencies") or [])
    for name, req in runtime_input.items():
        packaged = pyproject_runtime.get(name)
        if packaged is None:
            issues.append(f"pyproject runtime dependency missing: {name}")
        elif _exact_pin(packaged) != _exact_pin(req):
            issues.append(f"pyproject runtime dependency drift: {name}: input={req!s} package={packaged!s}")
    unexpected_packaged = sorted(set(pyproject_runtime) - set(runtime_input))
    if unexpected_packaged:
        issues.append("pyproject has unexpected runtime dependencies: " + ", ".join(unexpected_packaged))

    sbom = json.loads((ROOT / "bom.cdx.json").read_text(encoding="utf-8"))
    sbom_versions = {
        canonicalize_name(str(component.get("name") or "")): str(component.get("version") or "")
        for component in sbom.get("components") or []
    }
    for name, version in runtime_versions.items():
        if sbom_versions.get(name) != version:
            issues.append(f"SBOM runtime dependency drift: {name}: lock={version!r} sbom={sbom_versions.get(name)!r}")

    return issues


def summary(*, check_installed: bool = False) -> dict[str, object]:
    issues = consistency_issues(check_installed=check_installed)
    return {
        "format": "vulnflow-dependency-lock/1",
        "python": PYTHON_VERSION_FILE.read_text(encoding="utf-8").strip(),
        "runtime_locked_packages": len(_mapping(_requirements(RUNTIME_LOCK))),
        "development_locked_packages": len(_mapping(_requirements(DEV_LOCK, follow_includes=True))),
        "installed_environment_checked": check_installed,
        "passed": not issues,
        "issues": issues,
        "artifact_hashes": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-installed", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = summary(check_installed=args.check_installed)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    elif payload["passed"]:
        print("dependency lock consistency passed")
    else:
        print("dependency lock consistency failed")
        for issue in payload["issues"]:
            print(f"- {issue}")
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
