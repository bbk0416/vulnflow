from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the public repository SHA256SUMS manifest.")
    parser.add_argument("--manifest", default="SHA256SUMS.txt")
    args = parser.parse_args()
    manifest = ROOT / args.manifest
    if not manifest.is_file():
        raise SystemExit(f"manifest missing: {manifest}")

    checked = 0
    failures: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        match = LINE.fullmatch(raw)
        if not match:
            failures.append(f"line {number}: invalid format")
            continue
        expected, relative = match.groups()
        if relative in seen:
            failures.append(f"line {number}: duplicate path: {relative}")
            continue
        seen.add(relative)
        candidate = (ROOT / relative).resolve()
        try:
            candidate.relative_to(ROOT.resolve())
        except ValueError:
            failures.append(f"line {number}: path escapes repository: {relative}")
            continue
        if not candidate.is_file():
            failures.append(f"missing: {relative}")
            continue
        actual = _sha256(candidate)
        if actual != expected:
            failures.append(f"hash mismatch: {relative}")
        checked += 1

    print(f"public manifest checked: {checked}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        raise SystemExit(1)
    print("public manifest verification: PASS")


if __name__ == "__main__":
    main()
