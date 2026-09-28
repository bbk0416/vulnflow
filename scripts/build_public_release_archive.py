from __future__ import annotations

"""Build a release ZIP only from the exact Git HEAD blobs in SHA256SUMS.txt."""

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
FORBIDDEN_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def _git_bytes(relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"HEAD:{relative}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git blob unavailable for {relative}: "
            + result.stderr.decode("utf-8", errors="replace")[-1000:]
        )
    return result.stdout


def _git_modes() -> dict[str, int]:
    result = subprocess.run(
        ["git", "ls-tree", "-rz", "--full-tree", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    modes: dict[str, int] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        relative = raw_path.decode("utf-8")
        modes[relative] = 0o755 if mode == "100755" else 0o644
    return modes


def _manifest() -> tuple[bytes, dict[str, str]]:
    raw = _git_bytes("SHA256SUMS.txt")
    entries: dict[str, str] = {}
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError(f"invalid manifest line {number}")
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or any(part in FORBIDDEN_PARTS for part in path.parts):
            raise ValueError(f"unsafe manifest path: {relative}")
        if relative in entries:
            raise ValueError(f"duplicate manifest path: {relative}")
        entries[relative] = digest
    return raw, entries


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def build(output: Path) -> dict[str, object]:
    manifest_raw, manifest = _manifest()
    modes = _git_modes()
    version = _git_bytes("VERSION").decode("utf-8").strip()
    expected_name = f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip"
    if output.name != expected_name:
        raise ValueError(f"output must be named {expected_name}")

    blobs: dict[str, bytes] = {}
    for relative, expected in manifest.items():
        raw = _git_bytes(relative)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError(f"manifest mismatch before packaging: {relative}")
        blobs[relative] = raw

    root_name = output.stem
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(
            _zip_info(f"{root_name}/SHA256SUMS.txt", modes.get("SHA256SUMS.txt", 0o644)),
            manifest_raw,
            compresslevel=9,
        )
        for relative in sorted(blobs):
            archive.writestr(
                _zip_info(f"{root_name}/{relative}", modes.get(relative, 0o644)),
                blobs[relative],
                compresslevel=9,
            )

    expected_members = {
        f"{root_name}/SHA256SUMS.txt",
        *(f"{root_name}/{relative}" for relative in manifest),
    }
    with zipfile.ZipFile(output, "r") as archive:
        members = {info.filename for info in archive.infolist() if not info.is_dir()}
        if members != expected_members:
            missing = sorted(expected_members - members)
            extra = sorted(members - expected_members)
            raise ValueError(f"release member mismatch: missing={missing[:5]} extra={extra[:5]}")
        archived_manifest = archive.read(f"{root_name}/SHA256SUMS.txt")
        if archived_manifest != manifest_raw:
            raise ValueError("archived manifest bytes changed")
        for relative, expected in manifest.items():
            actual = hashlib.sha256(archive.read(f"{root_name}/{relative}")).hexdigest()
            if actual != expected:
                raise ValueError(f"archived manifest mismatch: {relative}")

    archive_digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return {
        "version": version,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "archive": output.name,
        "files": len(expected_members),
        "manifest_entries": len(manifest),
        "size_bytes": output.stat().st_size,
        "sha256": archive_digest,
        "source": "exact Git HEAD blobs",
        "verification": "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the exact-tree VulnFlow Windows release ZIP.")
    parser.add_argument("--output", default="")
    parser.add_argument("--json-output", default="")
    args = parser.parse_args()

    version = _git_bytes("VERSION").decode("utf-8").strip()
    output = (
        Path(args.output)
        if args.output
        else ROOT / "dist" / f"VulnFlow_Free_Public_Beta_Windows_Core_{version}.zip"
    )
    if not output.is_absolute():
        output = ROOT / output
    result = build(output)

    if args.json_output:
        json_output = Path(args.json_output)
        if not json_output.is_absolute():
            json_output = ROOT / json_output
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    for key in ("version", "head", "archive", "files", "manifest_entries", "size_bytes", "sha256", "verification"):
        print(f"{key}: {result[key]}")


if __name__ == "__main__":
    main()
