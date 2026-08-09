from __future__ import annotations

"""Generate the package-data manifest used for runtime dependency attestation."""

import argparse
import json
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
OUTPUT = ROOT / "app/resources/runtime_dependency_lock.json"
FORMAT = "vulnflow-runtime-dependency-lock/1"


def _condition(requirement: Requirement) -> str:
    marker = str(requirement.marker or "").replace("'", '"')
    if not marker:
        return "always"
    if marker == 'sys_platform == "win32"':
        return "windows"
    if marker in {
        'sys_platform != "win32" and platform_python_implementation == "CPython"',
        'platform_python_implementation == "CPython" and sys_platform != "win32"',
    }:
        return "cpython-non-windows"
    raise ValueError(f"unsupported runtime marker for packaged manifest: {marker}")


def build_manifest() -> dict[str, object]:
    packages: list[dict[str, str]] = []
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        pins = list(requirement.specifier)
        if len(pins) != 1 or pins[0].operator != "==" or pins[0].version.endswith(".*"):
            raise ValueError(f"runtime lock entry is not an exact pin: {line}")
        packages.append(
            {
                "name": canonicalize_name(requirement.name),
                "version": pins[0].version,
                "condition": _condition(requirement),
            }
        )
    packages.sort(key=lambda item: item["name"])
    return {
        "format": FORMAT,
        "application_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "python": {"minimum": "3.12", "maximum_exclusive": "3.14"},
        "packages": packages,
    }


def rendered() -> str:
    return json.dumps(build_manifest(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            print("runtime dependency manifest is stale")
            return 1
        print("runtime dependency manifest: PASS")
        return 0
    if args.write or not args.check:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
