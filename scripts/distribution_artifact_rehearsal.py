from __future__ import annotations

"""Build, normalize, install, and execute VulnFlow distribution artifacts."""

import argparse
import base64
from dataclasses import dataclass
import gzip
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
from typing import Any
import zipfile

import requests

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REPORT_JSON = ROOT / "reports" / "distribution_artifact_rehearsal_verification.json"
REPORT_TEXT = ROOT / "reports" / "distribution_artifact_rehearsal_verification.txt"
DIST_DIR = ROOT / "dist"
SOURCE_DATE_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
PACKAGE_NAME = "bbk-vulnflow"
EXPECTED_SCHEMA_VERSION = 40


@dataclass(frozen=True)
class BuiltArtifacts:
    wheel: Path
    sdist: Path
    wheel_sha256: str
    sdist_sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _clean_build_state(root: Path) -> None:
    shutil.rmtree(root / "build", ignore_errors=True)
    for path in root.glob("*.egg-info"):
        shutil.rmtree(path, ignore_errors=True)
    for path in root.rglob("__pycache__"):
        shutil.rmtree(path, ignore_errors=True)
    for path in root.rglob("*.py[co]"):
        path.unlink(missing_ok=True)


def normalize_sdist(source: Path, destination: Path, *, epoch: int = SOURCE_DATE_EPOCH) -> None:
    """Rewrite a setuptools sdist with stable gzip and tar metadata."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source, "r:gz") as archive:
        members = sorted(archive.getmembers(), key=lambda item: item.name)
        with destination.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                    for member in members:
                        if not _safe_member(member.name):
                            raise ValueError(f"unsafe sdist member: {member.name}")
                        cloned = tarfile.TarInfo(member.name)
                        cloned.size = member.size
                        cloned.mode = member.mode
                        cloned.type = member.type
                        cloned.linkname = member.linkname
                        cloned.mtime = epoch
                        cloned.uid = 0
                        cloned.gid = 0
                        cloned.uname = ""
                        cloned.gname = ""
                        cloned.pax_headers = {
                            key: value
                            for key, value in member.pax_headers.items()
                            if key not in {"atime", "ctime", "mtime", "SCHILY.dev", "SCHILY.ino", "SCHILY.nlink"}
                        }
                        fileobj = archive.extractfile(member) if member.isfile() else None
                        output.addfile(cloned, fileobj)


def _build_once(output: Path) -> BuiltArtifacts:
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("uv executable is required for offline distribution builds")
    _clean_build_state(ROOT)
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    raw = output / "raw"
    raw.mkdir()
    env = os.environ.copy()
    env.update({
        "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
        "PYTHONDONTWRITEBYTECODE": "1",
        "UV_OFFLINE": "1",
    })
    command = [
        uv,
        "build",
        "--python",
        sys.executable,
        "--offline",
        "--no-build-isolation",
        "--clear",
        "--no-build-logs",
        "--out-dir",
        str(raw),
        str(ROOT),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("distribution build failed:\n" + completed.stdout[-5000:])
    wheels = list(raw.glob("*.whl"))
    sdists = list(raw.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError(f"unexpected build artifacts: wheels={wheels}, sdists={sdists}")
    wheel = output / wheels[0].name
    sdist = output / sdists[0].name
    shutil.copy2(wheels[0], wheel)
    normalize_sdist(sdists[0], sdist)
    shutil.rmtree(raw, ignore_errors=True)
    _clean_build_state(ROOT)
    return BuiltArtifacts(wheel, sdist, sha256_file(wheel), sha256_file(sdist))


def _inspect_wheel(path: Path, version: str) -> dict[str, Any]:
    required = {
        "app/main.py",
        "app/cli.py",
        "app/templates/base.html",
        "app/static/style.css",
        "app/static/sample_findings.csv",
        "app/resources/prioritization_policy.yml",
    }
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        unsafe = [name for name in names if not _safe_member(name)]
        metadata_name = next((name for name in names if name.endswith(".dist-info/METADATA")), "")
        entry_name = next((name for name in names if name.endswith(".dist-info/entry_points.txt")), "")
        metadata_text = archive.read(metadata_name).decode("utf-8") if metadata_name else ""
        entry_text = archive.read(entry_name).decode("utf-8") if entry_name else ""
    return {
        "members": len(names),
        "unsafe_members": unsafe,
        "required_files_present": required.issubset(names),
        "missing_required_files": sorted(required - set(names)),
        "metadata_name": f"Name: {PACKAGE_NAME}" in metadata_text,
        "metadata_version": f"Version: {version}" in metadata_text,
        "console_entrypoint": "vulnflow = app.cli:main" in entry_text,
    }


def _inspect_sdist(path: Path, version: str) -> dict[str, Any]:
    prefix = f"bbk_vulnflow-{version}/"
    required = {
        prefix + "pyproject.toml",
        prefix + "README.md",
        prefix + "LICENSE",
        prefix + "VERSION",
        prefix + "app/main.py",
        prefix + "app/templates/base.html",
        prefix + "app/static/style.css",
        prefix + "app/resources/prioritization_policy.yml",
        prefix + "rules/prioritization_policy.yml",
        prefix + "scripts/verify_release.py",
        prefix + "tests/test_app_integration.py",
    }
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        unsafe = [member.name for member in members if not _safe_member(member.name)]
        timestamps = sorted({int(member.mtime) for member in members})
        owners = sorted({(member.uid, member.gid, member.uname, member.gname) for member in members})
    return {
        "members": len(names),
        "unsafe_members": unsafe,
        "required_files_present": required.issubset(names),
        "missing_required_files": sorted(required - names),
        "normalized_timestamps": timestamps == [SOURCE_DATE_EPOCH],
        "normalized_owners": owners == [(0, 0, "", "")],
    }


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _wait_ready(base_url: str, process: subprocess.Popen[Any], log_path: Path) -> None:
    deadline = time.monotonic() + 30
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"installed console process exited early: {process.returncode}\n{log[-4000:]}")
        try:
            response = requests.get(base_url + "/health/ready", timeout=1)
            if response.status_code == 200:
                return
            last_error = f"status={response.status_code}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(f"installed console process did not become ready: {last_error}")


def _terminate(process: subprocess.Popen[Any]) -> int:
    started = time.monotonic()
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)
        raise RuntimeError("installed console process exceeded SIGTERM deadline")
    return int((time.monotonic() - started) * 1000)


def _installed_probe(venv_python: Path, run_dir: Path, source_root: Path) -> dict[str, Any]:
    code = r'''
import json
from importlib import metadata
from pathlib import Path
import app
from app.core import settings
from app.services.recovery import _app_version
print(json.dumps({
  "distribution_version": metadata.version("bbk-vulnflow"),
  "application_version": _app_version(),
  "app_file": str(Path(app.__file__).resolve()),
  "policy_path": str(settings.POLICY_PATH.resolve()),
  "policy_exists": settings.POLICY_PATH.is_file(),
  "sample_path": str(settings.SAMPLE_PATH.resolve()),
  "sample_exists": settings.SAMPLE_PATH.is_file(),
  "template_exists": (settings.APP_DIR / "templates" / "base.html").is_file(),
  "static_exists": (settings.APP_DIR / "static" / "style.css").is_file(),
}, sort_keys=True))
'''
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    completed = subprocess.run(
        [str(venv_python), "-c", code],
        cwd=run_dir,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("installed package probe failed:\n" + completed.stdout[-4000:])
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    payload["outside_source_tree"] = not Path(payload["app_file"]).is_relative_to(source_root)
    return payload


def _install_and_run(wheel: Path, version: str, workspace: Path) -> dict[str, Any]:
    venv = workspace / "venv"
    run_dir = workspace / "runtime"
    run_dir.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=120)
    venv_python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    venv_bin = venv / ("Scripts" if os.name == "nt" else "bin")
    purelib = subprocess.check_output(
        [str(venv_python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        text=True,
    ).strip()
    host_paths = [path for path in sys.path if path and "site-packages" in path and Path(path).is_dir()]
    if not host_paths:
        raise RuntimeError("verified host site-packages path was not found")
    Path(purelib, "verified_host_dependencies.pth").write_text(
        "\n".join(dict.fromkeys(host_paths)) + "\n", encoding="utf-8"
    )
    install = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--no-index", "--no-deps", "--force-reinstall", str(wheel)],
        cwd=run_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    if install.returncode != 0:
        raise RuntimeError("wheel installation failed:\n" + install.stdout[-4000:])

    data = run_dir / "data"
    for relative in ("", "evidence", "recovery", "exports"):
        (data / relative).mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH" and not key.startswith("VULNFLOW_")}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "VULNFLOW_HOST": "127.0.0.1",
        "VULNFLOW_PORT": str(_free_port()),
        "VULNFLOW_DB": str(data / "vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(data / "coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(data / "evidence"),
        "VULNFLOW_RECOVERY_DIR": str(data / "recovery"),
        "VULNFLOW_EXPORT_DIR": str(data / "exports"),
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
        "VULNFLOW_USERS_JSON": json.dumps({
            "artifact-admin": {"password": "artifact-admin-pass-72-0-6", "role": "admin"}
        }),
        "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
        "VULNFLOW_JOB_WORKER_ENABLED": "0",
        "VULNFLOW_COOKIE_SECURE": "0",
        "VULNFLOW_CURSOR_SIGNING_KEY": "artifact-cursor-key-72-0-6",
        "VULNFLOW_AUDIT_SIGNING_KEY": "artifact-audit-key-72-0-6",
        "VULNFLOW_BACKUP_SIGNING_KEY": "artifact-backup-key-72-0-6",
    })
    port = int(env["VULNFLOW_PORT"])
    base_url = f"http://127.0.0.1:{port}"
    log_path = run_dir / "installed-console.log"
    executable = venv_bin / ("vulnflow.exe" if os.name == "nt" else "vulnflow")
    probe = _installed_probe(venv_python, run_dir, ROOT)
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [str(executable)],
            cwd=run_dir,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=(os.name == "posix"),
        )
    try:
        _wait_ready(base_url, process, log_path)
        live = requests.get(base_url + "/health/live", timeout=3).status_code
        ready = requests.get(base_url + "/health/ready", timeout=3).status_code
        anonymous = requests.get(base_url + "/", timeout=3).status_code
        authenticated = requests.get(
            base_url + "/",
            headers=_basic("artifact-admin", "artifact-admin-pass-72-0-6"),
            timeout=5,
        ).status_code
    finally:
        shutdown_ms = _terminate(process) if process.poll() is None else 0
    database = data / "vulnflow.db"
    with sqlite3.connect(database) as connection:
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    return {
        "install_output_tail": install.stdout[-1000:],
        "console_entrypoint_exists": executable.is_file(),
        "probe": probe,
        "live_status": live,
        "ready_status": ready,
        "anonymous_root_status": anonymous,
        "authenticated_root_status": authenticated,
        "shutdown_ms": shutdown_ms,
        "schema_version": schema,
        "sqlite_integrity": integrity,
        "log_tail": log_path.read_text(encoding="utf-8", errors="replace")[-2000:],
        "expected_version": version,
    }


def run_rehearsal(*, keep_workspace: bool = False) -> dict[str, Any]:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workspace_obj = tempfile.TemporaryDirectory(prefix="vulnflow-distribution-")
    workspace = Path(workspace_obj.name)
    try:
        first = _build_once(workspace / "build-a")
        second = _build_once(workspace / "build-b")
        wheel_info = _inspect_wheel(first.wheel, version)
        sdist_info = _inspect_sdist(first.sdist, version)
        installed = _install_and_run(first.wheel, version, workspace / "installed")

        checks = {
            "pyproject_version_matches": f'version = "{version}"' in pyproject,
            "wheel_reproducible": first.wheel_sha256 == second.wheel_sha256,
            "sdist_reproducible": first.sdist_sha256 == second.sdist_sha256,
            "wheel_paths_safe": not wheel_info["unsafe_members"],
            "sdist_paths_safe": not sdist_info["unsafe_members"],
            "wheel_runtime_files_complete": wheel_info["required_files_present"],
            "sdist_source_files_complete": sdist_info["required_files_present"],
            "wheel_metadata_name": wheel_info["metadata_name"],
            "wheel_metadata_version": wheel_info["metadata_version"],
            "wheel_console_entrypoint": wheel_info["console_entrypoint"],
            "sdist_timestamps_normalized": sdist_info["normalized_timestamps"],
            "sdist_owners_normalized": sdist_info["normalized_owners"],
            "installed_module_outside_source": installed["probe"]["outside_source_tree"],
            "installed_metadata_version": installed["probe"]["distribution_version"] == version,
            "installed_application_version": installed["probe"]["application_version"] == version,
            "installed_policy_resource": installed["probe"]["policy_exists"],
            "installed_sample_resource": installed["probe"]["sample_exists"],
            "installed_template_and_static": installed["probe"]["template_exists"] and installed["probe"]["static_exists"],
            "installed_console_entrypoint": installed["console_entrypoint_exists"],
            "installed_health_live": installed["live_status"] == 200,
            "installed_health_ready": installed["ready_status"] == 200,
            "installed_auth_default_closed": installed["anonymous_root_status"] == 401,
            "installed_authenticated_root": installed["authenticated_root_status"] == 200,
            "installed_sigterm_bounded": installed["shutdown_ms"] <= 12_000,
            "installed_database_schema": installed["schema_version"] == EXPECTED_SCHEMA_VERSION,
            "installed_database_integrity": installed["sqlite_integrity"] == "ok",
        }
        passed = all(checks.values())
        if passed:
            shutil.rmtree(DIST_DIR, ignore_errors=True)
            DIST_DIR.mkdir(parents=True)
            final_wheel = DIST_DIR / first.wheel.name
            final_sdist = DIST_DIR / first.sdist.name
            shutil.copy2(first.wheel, final_wheel)
            shutil.copy2(first.sdist, final_sdist)
            sums = {
                final_wheel.name: sha256_file(final_wheel),
                final_sdist.name: sha256_file(final_sdist),
            }
            (DIST_DIR / "SHA256SUMS.txt").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())), encoding="utf-8"
            )
        else:
            sums = {}
        return {
            "format": "vulnflow-distribution-artifact-rehearsal/1",
            "version": version,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "passed": passed,
            "checks_passed": sum(checks.values()),
            "checks_total": len(checks),
            "checks": checks,
            "artifacts": {
                "wheel": first.wheel.name,
                "wheel_sha256": first.wheel_sha256,
                "sdist": first.sdist.name,
                "sdist_sha256": first.sdist_sha256,
                "published_sha256": sums,
            },
            "wheel": wheel_info,
            "sdist": sdist_info,
            "installed": installed,
            "offline_dependency_mode": "isolated application venv with verified host dependency bridge",
            "limitations": [
                "dependency wheels were not downloaded or installed from a package index",
                "artifact installation used the already verified host dependency set through a venv .pth bridge",
                "Linux wheel and sdist reproducibility does not prove Windows artifact reproducibility",
            ],
        }
    finally:
        _clean_build_state(ROOT)
        if keep_workspace:
            print(f"workspace retained: {workspace}")
            workspace_obj.cleanup = lambda: None  # type: ignore[method-assign]
        else:
            workspace_obj.cleanup()


def _write_reports(payload: dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    artifacts = payload["artifacts"]
    installed = payload["installed"]
    lines = [
        f"VulnFlow {payload['version']} distribution artifact rehearsal",
        "",
        f"status: {'PASS' if payload['passed'] else 'FAIL'}",
        f"checks: {payload['checks_passed']}/{payload['checks_total']}",
        f"wheel: {artifacts['wheel']}",
        f"wheel_sha256: {artifacts['wheel_sha256']}",
        f"sdist: {artifacts['sdist']}",
        f"sdist_sha256: {artifacts['sdist_sha256']}",
        f"installed_version: {installed['probe']['distribution_version']}",
        f"installed_app_file: {installed['probe']['app_file']}",
        f"live_status: {installed['live_status']}",
        f"ready_status: {installed['ready_status']}",
        f"anonymous_root_status: {installed['anonymous_root_status']}",
        f"authenticated_root_status: {installed['authenticated_root_status']}",
        f"shutdown_ms: {installed['shutdown_ms']}",
        f"schema_version: {installed['schema_version']}",
        f"sqlite_integrity: {installed['sqlite_integrity']}",
        "",
        "limitations:",
    ]
    lines.extend(f"- {item}" for item in payload["limitations"])
    REPORT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-workspace", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = run_rehearsal(keep_workspace=args.keep_workspace)
    _write_reports(payload)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"distribution artifact rehearsal: {payload['checks_passed']}/{payload['checks_total']}")
        print(f"wheel sha256: {payload['artifacts']['wheel_sha256']}")
        print(f"sdist sha256: {payload['artifacts']['sdist_sha256']}")
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
