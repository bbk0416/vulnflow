from __future__ import annotations

"""Build a platform wheelhouse, reinstall it offline, and run a source smoke.

This is intentionally separate from the static dependency-lock check. Exact
pins alone do not prove that a clean machine can download a complete artifact
set or reinstall it without consulting an index. Public CI runs the strict default command. Restricted workspaces may use
``--allow-index-unavailable`` only to record the unavailable state; that result
is not a pass.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "vulnflow-dependency-wheelhouse-rehearsal/1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _venv_python(path: Path) -> Path:
    return path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _run(command: list[str], *, cwd: Path, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def wheelhouse_manifest(directory: Path) -> list[dict[str, Any]]:
    files = sorted(path for path in directory.iterdir() if path.is_file())
    return [
        {"filename": path.name, "size": path.stat().st_size, "sha256": _sha256(path)}
        for path in files
    ]


def _write_report(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a clean offline reinstall from the pinned dependency locks.")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--allow-index-unavailable",
        action="store_true",
        help="Record an unavailable index as a non-passing report instead of exiting non-zero.",
    )
    parser.add_argument("--index-url", default="", help="Optional explicit package index URL.")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    started = time.monotonic()
    payload: dict[str, Any] = {
        "format": FORMAT,
        "status": "failed",
        "passed": False,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": sys.platform,
        "wheelhouse": [],
        "checks": [],
    }

    def check(name: str, passed: bool, detail: str = "") -> None:
        payload["checks"].append({"name": name, "passed": bool(passed), "detail": detail})

    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow-wheelhouse-") as temp_value:
            temp = Path(temp_value)
            wheelhouse = temp / "wheelhouse"
            environment = temp / "venv"
            wheelhouse.mkdir()

            download = [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--only-binary=:all:",
                "--dest",
                str(wheelhouse),
                "-r",
                str(ROOT / "requirements-dev.lock"),
            ]
            if args.index_url:
                download[4:4] = ["--index-url", args.index_url]
            downloaded = _run(download, cwd=ROOT, timeout=args.timeout_seconds)
            payload["download_output_tail"] = downloaded.stdout[-4000:]
            if downloaded.returncode:
                payload["status"] = "index-unavailable"
                check("download_complete", False, f"pip exit {downloaded.returncode}")
                payload["duration_seconds"] = round(time.monotonic() - started, 3)
                _write_report(args.json_output, payload)
                print("dependency wheelhouse rehearsal: INDEX UNAVAILABLE", file=sys.stderr)
                print(downloaded.stdout[-2000:], file=sys.stderr)
                return 0 if args.allow_index_unavailable else downloaded.returncode

            artifacts = wheelhouse_manifest(wheelhouse)
            payload["wheelhouse"] = artifacts
            check("download_complete", bool(artifacts), f"{len(artifacts)} artifacts")
            check("artifact_names_unique", len({item["filename"] for item in artifacts}) == len(artifacts))
            check("artifact_hashes_recorded", all(len(item["sha256"]) == 64 for item in artifacts))

            venv.EnvBuilder(with_pip=True, clear=True).create(environment)
            python = _venv_python(environment)
            installed = _run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(wheelhouse),
                    "-r",
                    str(ROOT / "requirements-dev.lock"),
                ],
                cwd=ROOT,
                timeout=args.timeout_seconds,
            )
            payload["install_output_tail"] = installed.stdout[-4000:]
            check("offline_install", installed.returncode == 0, f"pip exit {installed.returncode}")
            if installed.returncode:
                raise RuntimeError("offline wheelhouse installation failed")

            lock_check = _run(
                [str(python), "scripts/dependency_lock.py", "--check-installed", "--json"],
                cwd=ROOT,
                timeout=180,
            )
            payload["lock_check_output"] = lock_check.stdout[-4000:]
            check("installed_versions_match_lock", lock_check.returncode == 0)
            if lock_check.returncode:
                raise RuntimeError("installed dependency versions do not match the lock")

            imports = _run(
                [
                    str(python),
                    "-c",
                    (
                        "import app.main, fastapi, starlette, cryptography, openpyxl; "
                        "print(app.main.CURRENT_APP_VERSION)"
                    ),
                ],
                cwd=ROOT,
                timeout=120,
            )
            payload["import_output"] = imports.stdout[-2000:]
            check("application_import", imports.returncode == 0)
            if imports.returncode:
                raise RuntimeError("application import failed in the clean environment")

            smoke = _run(
                [
                    str(python),
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "tests/test_app_integration.py",
                    "tests/test_distribution_install_boundaries_v93.py",
                ],
                cwd=ROOT,
                timeout=300,
            )
            payload["smoke_output_tail"] = smoke.stdout[-4000:]
            check("clean_environment_smoke", smoke.returncode == 0)
            if smoke.returncode:
                raise RuntimeError("clean-environment smoke tests failed")

            payload["status"] = "passed"
            payload["passed"] = all(item["passed"] for item in payload["checks"])
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        payload["error"] = str(exc)
        payload["passed"] = False
    finally:
        payload["duration_seconds"] = round(time.monotonic() - started, 3)
        _write_report(args.json_output, payload)

    if payload["passed"]:
        print(
            f"dependency wheelhouse rehearsal: PASS ({len(payload['wheelhouse'])} artifacts, "
            f"{payload['duration_seconds']}s)"
        )
        return 0
    print("dependency wheelhouse rehearsal: FAIL", file=sys.stderr)
    for item in payload["checks"]:
        if not item["passed"]:
            print(f"- {item['name']}: {item.get('detail', '')}", file=sys.stderr)
    if payload.get("error"):
        print(f"- {payload['error']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
