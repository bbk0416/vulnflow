from __future__ import annotations

"""Verify and snapshot the exact public source tree used for external validation.

The signed request binds SHA256SUMS.txt.  This module goes further and verifies
that every file listed by that manifest is still a regular, in-tree file whose
bytes match the signed manifest.  It also provides a private execution snapshot
so a runner does not execute directly from a mutable extracted kit directory.
"""

import hashlib
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.schema_versions import CURRENT_SCHEMA_VERSION

FORMAT = "vulnflow-external-validation-source-attestation/1"
MANIFEST_SEPARATOR = "  "


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and value not in {".", ""}
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in value
    )


def read_public_manifest(root: Path) -> dict[str, str]:
    manifest = root.resolve() / "SHA256SUMS.txt"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("source SHA256SUMS.txt is missing or not a regular file")
    entries: dict[str, str] = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        if len(line) < 67 or line[64:66] != MANIFEST_SEPARATOR:
            raise ValueError(f"invalid public manifest line {number}")
        digest, relative = line[:64], line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid public manifest digest at line {number}")
        if not _safe_relative(relative) or relative in entries:
            raise ValueError(f"unsafe or duplicate public manifest path at line {number}")
        entries[relative] = digest
    if not entries:
        raise ValueError("public source manifest is empty")
    return entries


def _linked_component(path: Path, root: Path) -> bool:
    current = path
    while current != root:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def attest_public_source(root: Path) -> dict[str, Any]:
    resolved_root = root.resolve()
    issues: list[str] = []
    try:
        entries = read_public_manifest(resolved_root)
    except (OSError, UnicodeError, ValueError) as exc:
        return {
            "format": FORMAT,
            "passed": False,
            "root": str(resolved_root),
            "identity": {},
            "manifest_entries": 0,
            "issues": [str(exc)],
        }

    actual_lines: list[str] = []
    for relative, expected in entries.items():
        candidate = resolved_root / relative
        try:
            actual = candidate.resolve(strict=True)
            actual.relative_to(resolved_root)
        except (OSError, ValueError):
            issues.append(f"missing or escaping source file: {relative}")
            continue
        if _linked_component(candidate, resolved_root) or not actual.is_file():
            issues.append(f"linked or non-regular source file: {relative}")
            continue
        digest = _sha256(actual)
        actual_lines.append(f"{digest}{MANIFEST_SEPARATOR}{relative}")
        if digest != expected:
            issues.append(f"source hash mismatch: {relative}")

    version_path = resolved_root / "VERSION"
    try:
        version = version_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        version = ""
        issues.append("source VERSION is missing or invalid")

    manifest_path = resolved_root / "SHA256SUMS.txt"
    canonical_tree = ("\n".join(sorted(actual_lines)) + "\n").encode("utf-8")
    identity = {
        "version": version,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "public_manifest_sha256": _sha256(manifest_path),
        "manifest_entries": len(entries),
        "verified_tree_sha256": _sha256_bytes(canonical_tree),
    }
    return {
        "format": FORMAT,
        "passed": not issues and len(actual_lines) == len(entries),
        "root": str(resolved_root),
        "identity": identity,
        "manifest_entries": len(entries),
        "issues": issues,
    }


def require_public_source(root: Path) -> dict[str, Any]:
    report = attest_public_source(root)
    if not report.get("passed"):
        raise ValueError("public source verification failed: " + "; ".join(report.get("issues", [])[:8]))
    return report


def copy_verified_public_source(source_root: Path, destination: Path) -> dict[str, Any]:
    source = source_root.resolve()
    target = destination.resolve()
    if destination.is_symlink():
        raise ValueError("execution snapshot must not be a symbolic link")
    if target.exists():
        raise ValueError("execution snapshot destination already exists")
    try:
        target.relative_to(source)
        raise ValueError("execution snapshot must be outside the source tree")
    except ValueError as exc:
        if str(exc) == "execution snapshot must be outside the source tree":
            raise

    before = require_public_source(source)
    entries = read_public_manifest(source)
    target.mkdir(parents=True, mode=0o700)
    try:
        for relative in sorted(entries):
            src = source / relative
            dst = target / relative
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            try:
                shutil.copymode(src, dst)
            except OSError:
                pass
        shutil.copyfile(source / "SHA256SUMS.txt", target / "SHA256SUMS.txt")
        after = require_public_source(target)
        if before["identity"] != after["identity"]:
            raise ValueError("execution snapshot identity differs from verified source")
        return after
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
