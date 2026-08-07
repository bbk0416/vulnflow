from __future__ import annotations

"""Runtime dependency attestation against the packaged VulnFlow lock manifest."""

from dataclasses import dataclass
from importlib import metadata, resources
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

MANIFEST_FORMAT = "vulnflow-runtime-dependency-lock/1"
SUPPORTED_POLICIES = frozenset({"off", "warn", "enforce"})


@dataclass(frozen=True, slots=True)
class RuntimeDependencyFinding:
    code: str
    package: str
    expected: str
    actual: str


@dataclass(frozen=True, slots=True)
class RuntimeDependencyReport:
    policy: str
    checked: bool
    expected_packages: int
    findings: tuple[RuntimeDependencyFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "checked": self.checked,
            "passed": self.passed,
            "expected_packages": self.expected_packages,
            "findings": [
                {
                    "code": item.code,
                    "package": item.package,
                    "expected": item.expected,
                    "actual": item.actual,
                }
                for item in self.findings
            ],
        }


def load_runtime_dependency_manifest(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        text = resources.files("app").joinpath("resources/runtime_dependency_lock.json").read_text(
            encoding="utf-8"
        )
    else:
        text = path.read_text(encoding="utf-8")
    payload = json.loads(text)
    if payload.get("format") != MANIFEST_FORMAT:
        raise ValueError("지원하지 않는 런타임 의존성 manifest 형식입니다.")
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("런타임 의존성 manifest가 비어 있습니다.")
    return payload


def _condition_applies(
    condition: str,
    *,
    platform_name: str,
    implementation_name: str,
) -> bool:
    normalized = str(condition or "always").strip().lower()
    if normalized == "always":
        return True
    if normalized == "windows":
        return platform_name == "win32"
    if normalized == "cpython-non-windows":
        return platform_name != "win32" and implementation_name.lower() == "cpython"
    raise ValueError(f"지원하지 않는 런타임 의존성 조건입니다: {condition}")


def evaluate_runtime_dependencies(
    *,
    policy: str,
    manifest: Mapping[str, Any] | None = None,
    version_lookup: Callable[[str], str] = metadata.version,
    platform_name: str | None = None,
    implementation_name: str | None = None,
) -> RuntimeDependencyReport:
    normalized_policy = str(policy or "off").strip().lower()
    if normalized_policy not in SUPPORTED_POLICIES:
        raise ValueError("VULNFLOW_RUNTIME_DEPENDENCY_POLICY는 off, warn, enforce 중 하나여야 합니다.")
    if normalized_policy == "off":
        return RuntimeDependencyReport(normalized_policy, False, 0, ())

    payload = dict(manifest or load_runtime_dependency_manifest())
    current_platform = platform_name or sys.platform
    current_implementation = implementation_name or sys.implementation.name
    active: list[Mapping[str, Any]] = []
    for raw in payload.get("packages") or []:
        item = dict(raw)
        if _condition_applies(
            str(item.get("condition") or "always"),
            platform_name=current_platform,
            implementation_name=current_implementation,
        ):
            active.append(item)

    findings: list[RuntimeDependencyFinding] = []
    for item in active:
        name = str(item.get("name") or "").strip()
        expected = str(item.get("version") or "").strip()
        if not name or not expected:
            raise ValueError("런타임 의존성 manifest 항목이 올바르지 않습니다.")
        try:
            actual = str(version_lookup(name))
        except metadata.PackageNotFoundError:
            findings.append(RuntimeDependencyFinding("dependency.missing", name, expected, "missing"))
            continue
        if actual != expected:
            findings.append(RuntimeDependencyFinding("dependency.version", name, expected, actual))

    return RuntimeDependencyReport(normalized_policy, True, len(active), tuple(findings))


def enforce_runtime_dependencies(
    *,
    policy: str,
    manifest: Mapping[str, Any] | None = None,
    version_lookup: Callable[[str], str] = metadata.version,
) -> RuntimeDependencyReport:
    report = evaluate_runtime_dependencies(
        policy=policy,
        manifest=manifest,
        version_lookup=version_lookup,
    )
    if report.policy == "enforce" and not report.passed:
        details = "; ".join(
            f"{item.package}: expected={item.expected}, actual={item.actual}"
            for item in report.findings
        )
        raise RuntimeError(f"런타임 의존성 검증 실패: {details}")
    return report


__all__ = [
    "MANIFEST_FORMAT",
    "RuntimeDependencyFinding",
    "RuntimeDependencyReport",
    "enforce_runtime_dependencies",
    "evaluate_runtime_dependencies",
    "load_runtime_dependency_manifest",
]
