from __future__ import annotations

"""Build and verify a deterministic offline runtime dependency snapshot.

The snapshot is intentionally platform specific. It captures the exact installed
files for the active entries in ``requirements.lock`` and restores them into a
clean virtual environment without a host ``site-packages`` bridge.
"""

import argparse
import gzip
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
from typing import Any, Iterable

from packaging.requirements import Requirement
import requests

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.distribution_artifact_rehearsal import SOURCE_DATE_EPOCH, sha256_file

SNAPSHOT_FORMAT = "vulnflow-runtime-dependency-snapshot/1"
REPORT_JSON = ROOT / "reports" / "runtime_dependency_snapshot_verification.json"
REPORT_TEXT = ROOT / "reports" / "runtime_dependency_snapshot_verification.txt"
DIST_DIR = ROOT / "dist"
LOCK_PATH = ROOT / "requirements.lock"
ARCHIVE_PREFIX = "vulnflow-runtime-snapshot"


def canonical_name(value: str) -> str:
    return "-".join(part for part in __import__("re").split(r"[-_.]+", value.lower()) if part)


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def active_locked_requirements(path: Path = LOCK_PATH) -> list[Requirement]:
    requirements: list[Requirement] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        pins = list(requirement.specifier)
        if len(pins) != 1 or pins[0].operator != "==" or pins[0].version.endswith(".*"):
            raise ValueError(f"runtime lock entry is not an exact pin: {line}")
        requirements.append(requirement)
    return sorted(requirements, key=lambda item: canonical_name(item.name))


def platform_identity() -> dict[str, str]:
    libc_name, libc_version = platform.libc_ver()
    return {
        "implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "python_abi": str(sysconfig.get_config_var("SOABI") or ""),
        "python_tag": f"cp{sys.version_info.major}{sys.version_info.minor}",
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
        "platform_tag": sysconfig.get_platform().replace("-", "_").replace(".", "_"),
        "libc": libc_name,
        "libc_version": libc_version,
    }


def snapshot_archive_name(version: str, identity: dict[str, str] | None = None) -> str:
    identity = identity or platform_identity()
    return (
        f"vulnflow_runtime_dependencies-{version}-"
        f"{identity['python_tag']}-{identity['platform_tag']}.tar.gz"
    )


def _site_roots() -> list[Path]:
    values = {
        Path(value).resolve()
        for value in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"))
        if value
    }
    roots = sorted((path for path in values if path.is_dir()), key=lambda path: len(str(path)), reverse=True)
    if not roots:
        raise RuntimeError("active site-packages roots were not found")
    return roots


def _relative_to_site(path: Path, roots: Iterable[Path]) -> str | None:
    absolute = Path(os.path.abspath(path))
    for root in roots:
        try:
            relative = absolute.relative_to(root)
        except ValueError:
            continue
        value = relative.as_posix()
        if _safe_member(value):
            return value
    return None


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_snapshot() -> tuple[dict[str, Any], dict[str, Path]]:
    roots = _site_roots()
    file_sources: dict[str, Path] = {}
    file_records: dict[str, dict[str, Any]] = {}
    package_records: list[dict[str, Any]] = []
    for requirement in active_locked_requirements():
        pin = next(iter(requirement.specifier)).version
        distribution = metadata.distribution(requirement.name)
        if distribution.version != pin:
            raise RuntimeError(
                f"installed dependency drift: {requirement.name}: "
                f"installed={distribution.version!r} lock={pin!r}"
            )
        package_paths: list[str] = []
        package_bytes = 0
        for item in sorted(distribution.files or (), key=lambda value: str(value)):
            located = Path(distribution.locate_file(item))
            relative = _relative_to_site(located, roots)
            if relative is None or "__pycache__" in PurePosixPath(relative).parts or relative.endswith((".pyc", ".pyo")):
                continue
            if not located.is_file() or located.is_symlink():
                continue
            data = located.read_bytes()
            digest = _hash_bytes(data)
            executable = bool(located.stat().st_mode & stat.S_IXUSR)
            existing = file_records.get(relative)
            owner = canonical_name(requirement.name)
            if existing is not None:
                if existing["sha256"] != digest or existing["size"] != len(data):
                    raise RuntimeError(f"conflicting dependency file ownership: {relative}")
                existing["owners"] = sorted(set(existing["owners"] + [owner]))
            else:
                file_sources[relative] = located
                file_records[relative] = {
                    "path": relative,
                    "sha256": digest,
                    "size": len(data),
                    "mode": "0755" if executable else "0644",
                    "owners": [owner],
                }
            package_paths.append(relative)
            package_bytes += len(data)
        if not package_paths:
            raise RuntimeError(f"no site-packages files found for {requirement.name}")
        package_records.append({
            "name": str(distribution.metadata.get("Name") or requirement.name),
            "canonical_name": canonical_name(requirement.name),
            "version": distribution.version,
            "files": len(set(package_paths)),
            "bytes": package_bytes,
        })
    files = [file_records[path] for path in sorted(file_records)]
    manifest: dict[str, Any] = {
        "format": SNAPSHOT_FORMAT,
        "application_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "platform": platform_identity(),
        "requirements_lock_sha256": sha256_file(LOCK_PATH),
        "packages": sorted(package_records, key=lambda item: item["canonical_name"]),
        "package_count": len(package_records),
        "files": files,
        "file_count": len(files),
        "total_bytes": sum(int(item["size"]) for item in files),
    }
    manifest["content_manifest_sha256"] = _hash_bytes(_json_bytes({
        "packages": manifest["packages"],
        "files": manifest["files"],
    }))
    return manifest, file_sources


def build_snapshot_archive(destination: Path) -> dict[str, Any]:
    manifest, sources = collect_snapshot()
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest_bytes = _json_bytes(manifest)
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=SOURCE_DATE_EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                manifest_info = tarfile.TarInfo(f"{ARCHIVE_PREFIX}/manifest.json")
                manifest_info.size = len(manifest_bytes)
                manifest_info.mode = 0o644
                manifest_info.mtime = SOURCE_DATE_EPOCH
                manifest_info.uid = manifest_info.gid = 0
                manifest_info.uname = manifest_info.gname = ""
                archive.addfile(manifest_info, __import__("io").BytesIO(manifest_bytes))
                for record in manifest["files"]:
                    relative = str(record["path"])
                    source = sources[relative]
                    data = source.read_bytes()
                    info = tarfile.TarInfo(f"{ARCHIVE_PREFIX}/site-packages/{relative}")
                    info.size = len(data)
                    info.mode = int(str(record["mode"]), 8)
                    info.mtime = SOURCE_DATE_EPOCH
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, __import__("io").BytesIO(data))
    return manifest


def inspect_snapshot_archive(path: Path) -> dict[str, Any]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        unsafe = [name for name in names if not _safe_member(name)]
        manifest_member = archive.getmember(f"{ARCHIVE_PREFIX}/manifest.json")
        manifest_file = archive.extractfile(manifest_member)
        if manifest_file is None:
            raise RuntimeError("snapshot manifest is unreadable")
        manifest = json.loads(manifest_file.read())
        expected = {f"{ARCHIVE_PREFIX}/site-packages/{item['path']}": item for item in manifest["files"]}
        actual_file_names = {member.name for member in members if member.isfile() and member.name != manifest_member.name}
        missing = sorted(set(expected) - actual_file_names)
        unexpected = sorted(actual_file_names - set(expected))
        mismatched: list[str] = []
        normalized = True
        for member in members:
            normalized = normalized and int(member.mtime) == SOURCE_DATE_EPOCH
            normalized = normalized and (member.uid, member.gid, member.uname, member.gname) == (0, 0, "", "")
            if member.name not in expected:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                mismatched.append(member.name)
                continue
            data = handle.read()
            record = expected[member.name]
            if len(data) != int(record["size"]) or _hash_bytes(data) != record["sha256"]:
                mismatched.append(member.name)
    return {
        "manifest": manifest,
        "members": len(members),
        "unsafe_members": unsafe,
        "missing_files": missing,
        "unexpected_files": unexpected,
        "mismatched_files": mismatched,
        "normalized_metadata": normalized,
    }


def restore_snapshot(path: Path, purelib: Path) -> dict[str, Any]:
    inspection = inspect_snapshot_archive(path)
    manifest = inspection["manifest"]
    if inspection["unsafe_members"] or inspection["missing_files"] or inspection["unexpected_files"] or inspection["mismatched_files"]:
        raise RuntimeError("runtime snapshot archive failed integrity inspection")
    purelib.mkdir(parents=True, exist_ok=True)
    restored = 0
    with tarfile.open(path, "r:gz") as archive:
        for record in manifest["files"]:
            relative = str(record["path"])
            if not _safe_member(relative):
                raise RuntimeError(f"unsafe runtime snapshot path: {relative}")
            target = purelib / Path(*PurePosixPath(relative).parts)
            if target.exists():
                raise RuntimeError(f"clean venv contains conflicting dependency path: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            member = archive.getmember(f"{ARCHIVE_PREFIX}/site-packages/{relative}")
            handle = archive.extractfile(member)
            if handle is None:
                raise RuntimeError(f"snapshot member is unreadable: {relative}")
            data = handle.read()
            if _hash_bytes(data) != record["sha256"]:
                raise RuntimeError(f"snapshot member hash mismatch: {relative}")
            target.write_bytes(data)
            target.chmod(int(str(record["mode"]), 8))
            restored += 1
    return {"manifest": manifest, "restored_files": restored}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_ready(base_url: str, process: subprocess.Popen[Any], log_path: Path) -> None:
    deadline = time.monotonic() + 35
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"snapshot-restored process exited early: {process.returncode}\n{log[-4000:]}")
        try:
            response = requests.get(base_url + "/health/ready", timeout=1)
            if response.status_code == 200:
                return
            last_error = f"status={response.status_code}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(f"snapshot-restored process did not become ready: {last_error}")


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
        raise RuntimeError("snapshot-restored process exceeded SIGTERM deadline")
    return int((time.monotonic() - started) * 1000)


def _find_application_wheel(version: str) -> Path:
    wheels = sorted(DIST_DIR.glob(f"bbk_vulnflow-{version}-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one application wheel in dist/: {wheels}")
    return wheels[0]


def _probe_isolated_environment(venv_python: Path, run_dir: Path, manifest: dict[str, Any], purelib: Path) -> dict[str, Any]:
    names = [item["canonical_name"] for item in manifest["packages"]]
    expected = {item["canonical_name"]: item["version"] for item in manifest["packages"]}
    code = r'''
import json, os, site, sys
from importlib import metadata
from pathlib import Path
import app
names = json.loads(os.environ["VULNFLOW_SNAPSHOT_NAMES"])
expected = json.loads(os.environ["VULNFLOW_SNAPSHOT_VERSIONS"])
purelib = Path(os.environ["VULNFLOW_SNAPSHOT_PURELIB"]).resolve()
packages = {}
for name in names:
    dist = metadata.distribution(name)
    root = Path(dist.locate_file("")).resolve()
    packages[name] = {
        "version": dist.version,
        "root": str(root),
        "inside_venv": root == purelib or purelib in root.parents,
        "version_matches": dist.version == expected[name],
    }
print(json.dumps({
  "app_file": str(Path(app.__file__).resolve()),
  "sys_path": [str(Path(item).resolve()) for item in sys.path if item],
  "user_site_enabled": bool(site.ENABLE_USER_SITE),
  "packages": packages,
}, sort_keys=True))
'''
    env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "VULNFLOW_SNAPSHOT_NAMES": json.dumps(names),
        "VULNFLOW_SNAPSHOT_VERSIONS": json.dumps(expected),
        "VULNFLOW_SNAPSHOT_PURELIB": str(purelib),
    })
    completed = subprocess.run(
        [str(venv_python), "-s", "-c", code],
        cwd=run_dir,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("isolated runtime probe failed:\n" + completed.stdout[-5000:])
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _restore_install_and_run(snapshot: Path, wheel: Path, workspace: Path) -> dict[str, Any]:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    venv = workspace / "venv"
    run_dir = workspace / "runtime"
    run_dir.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=120)
    venv_python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    venv_bin = venv / ("Scripts" if os.name == "nt" else "bin")
    purelib = Path(subprocess.check_output(
        [str(venv_python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True,
    ).strip()).resolve()
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
        raise RuntimeError("application wheel installation failed:\n" + install.stdout[-4000:])
    restored = restore_snapshot(snapshot, purelib)
    probe = _probe_isolated_environment(venv_python, run_dir, restored["manifest"], purelib)

    data = run_dir / "data"
    default_project = data / "projects" / "default"
    for path in (data, default_project / "evidence", default_project / "backups" / "recovery", default_project / "exports"):
        path.mkdir(parents=True, exist_ok=True)
    username = "snapshot-admin"
    password = f"snapshot-admin-pass-{version}"
    env = {
        key: value for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME"} and not key.startswith("VULNFLOW_")
    }
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
        "VULNFLOW_HOST": "127.0.0.1",
        "VULNFLOW_PORT": str(_free_port()),
        "VULNFLOW_BASE_DIR": str(run_dir),
        "VULNFLOW_DATA_DIR": str(data),
        "VULNFLOW_DB": str(data / "legacy-vulnflow.db"),
        "VULNFLOW_CONTROL_DB": str(data / "control.db"),
        "VULNFLOW_PROJECTS_DIR": str(data / "projects"),
        "VULNFLOW_DEFAULT_PROJECT_ROOT": str(default_project),
        "VULNFLOW_DEFAULT_PROJECT_DB": str(default_project / "vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(data / "coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(default_project / "evidence"),
        "VULNFLOW_RECOVERY_DIR": str(default_project / "backups" / "recovery"),
        "VULNFLOW_EXPORT_DIR": str(default_project / "exports"),
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({username: {"token": password, "role": "admin", "projects": "*"}}),
        "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
        "VULNFLOW_JOB_WORKER_ENABLED": "0",
        "VULNFLOW_COOKIE_SECURE": "0",
        "VULNFLOW_CURSOR_SIGNING_KEY": f"snapshot-cursor-{version}",
        "VULNFLOW_AUDIT_SIGNING_KEY": f"snapshot-audit-{version}",
        "VULNFLOW_BACKUP_SIGNING_KEY": f"snapshot-backup-{version}",
    })
    port = int(env["VULNFLOW_PORT"])
    base_url = f"http://127.0.0.1:{port}"
    executable = venv_bin / ("vulnflow.exe" if os.name == "nt" else "vulnflow")
    log_path = run_dir / "runtime-snapshot-console.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [str(executable)],
            cwd=run_dir,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=False,
        )
    try:
        _wait_ready(base_url, process, log_path)
        live = requests.get(base_url + "/health/live", timeout=3).status_code
        ready = requests.get(base_url + "/health/ready", timeout=3).status_code
        anonymous = requests.get(base_url + "/", timeout=3).status_code
        authenticated = requests.get(base_url + "/", headers={"Authorization": f"Bearer {password}"}, timeout=5).status_code
    finally:
        shutdown_ms = _terminate(process) if process.poll() is None else 0
    database = default_project / "vulnflow.db"
    with sqlite3.connect(database) as connection:
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    host_roots = [str(path) for path in _site_roots()]
    sys_path = probe["sys_path"]
    return {
        "restored_files": restored["restored_files"],
        "purelib": str(purelib),
        "probe": probe,
        "host_site_packages_absent": not any(
            any(item == root or item.startswith(root + os.sep) for root in host_roots)
            for item in sys_path
        ),
        "all_locked_packages_inside_venv": all(item["inside_venv"] for item in probe["packages"].values()),
        "all_locked_versions_match": all(item["version_matches"] for item in probe["packages"].values()),
        "console_entrypoint_exists": executable.is_file(),
        "live_status": live,
        "ready_status": ready,
        "anonymous_root_status": anonymous,
        "authenticated_root_status": authenticated,
        "shutdown_ms": shutdown_ms,
        "schema_version": schema,
        "sqlite_integrity": integrity,
        "log_tail": log_path.read_text(encoding="utf-8", errors="replace")[-2000:],
    }


def run_rehearsal(*, keep_workspace: bool = False) -> dict[str, Any]:
    if sys.implementation.name != "cpython" or platform.system().lower() != "linux":
        raise RuntimeError("runtime dependency snapshot currently supports Linux CPython only")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    wheel = _find_application_wheel(version)
    identity = platform_identity()
    archive_name = snapshot_archive_name(version, identity)
    workspace_obj = tempfile.TemporaryDirectory(prefix="vulnflow-runtime-snapshot-")
    workspace = Path(workspace_obj.name)
    try:
        first_path = workspace / "first" / archive_name
        second_path = workspace / "second" / archive_name
        first_manifest = build_snapshot_archive(first_path)
        second_manifest = build_snapshot_archive(second_path)
        first_info = inspect_snapshot_archive(first_path)
        second_info = inspect_snapshot_archive(second_path)
        restored = _restore_install_and_run(first_path, wheel, workspace / "installed")
        checks = {
            "linux_cpython_platform": identity["system"] == "linux" and identity["implementation"] == "cpython",
            "python_tag_matches_runtime": identity["python_tag"] == f"cp{sys.version_info.major}{sys.version_info.minor}",
            "runtime_lock_hash_recorded": first_manifest["requirements_lock_sha256"] == sha256_file(LOCK_PATH),
            "active_lock_package_count": first_manifest["package_count"] >= 29,
            "snapshot_file_count_nontrivial": first_manifest["file_count"] >= 900,
            "snapshot_payload_nontrivial": first_manifest["total_bytes"] >= 40 * 1024 * 1024,
            "snapshot_archive_reproducible": sha256_file(first_path) == sha256_file(second_path),
            "snapshot_manifest_reproducible": first_manifest == second_manifest,
            "snapshot_paths_safe": not first_info["unsafe_members"],
            "snapshot_files_complete": not first_info["missing_files"] and not first_info["unexpected_files"],
            "snapshot_hashes_valid": not first_info["mismatched_files"],
            "snapshot_metadata_normalized": first_info["normalized_metadata"],
            "second_snapshot_integrity": not second_info["mismatched_files"],
            "manifest_content_digest_stable": first_manifest["content_manifest_sha256"] == second_manifest["content_manifest_sha256"],
            "restored_file_count": restored["restored_files"] == first_manifest["file_count"],
            "host_site_packages_bridge_absent": restored["host_site_packages_absent"],
            "locked_packages_inside_clean_venv": restored["all_locked_packages_inside_venv"],
            "locked_versions_match": restored["all_locked_versions_match"],
            "installed_app_outside_source": not Path(restored["probe"]["app_file"]).is_relative_to(ROOT),
            "installed_console_entrypoint": restored["console_entrypoint_exists"],
            "installed_health_live": restored["live_status"] == 200,
            "installed_health_ready": restored["ready_status"] == 200,
            "installed_auth_default_closed": restored["anonymous_root_status"] == 401,
            "installed_authenticated_root": restored["authenticated_root_status"] == 200,
            "installed_sigterm_bounded": restored["shutdown_ms"] <= 12_000,
            "installed_database_schema": restored["schema_version"] == CURRENT_SCHEMA_VERSION,
            "installed_database_integrity": restored["sqlite_integrity"] == "ok",
            "no_user_site_dependency": restored["probe"]["user_site_enabled"] is False,
        }
        passed = all(checks.values())
        published: dict[str, str] = {}
        if passed:
            final_archive = DIST_DIR / archive_name
            shutil.copy2(first_path, final_archive)
            manifest_path = DIST_DIR / "runtime_dependency_snapshot_manifest.json"
            manifest_path.write_text(json.dumps(first_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            sums_path = DIST_DIR / "RUNTIME_SNAPSHOT_SHA256SUMS.txt"
            published = {
                final_archive.name: sha256_file(final_archive),
                manifest_path.name: sha256_file(manifest_path),
            }
            sums_path.write_text(
                "".join(f"{digest}  {name}\n" for name, digest in sorted(published.items())),
                encoding="utf-8",
            )
            published[sums_path.name] = sha256_file(sums_path)
        return {
            "format": "vulnflow-runtime-dependency-snapshot-rehearsal/1",
            "version": version,
            "passed": passed,
            "checks_passed": sum(checks.values()),
            "checks_total": len(checks),
            "checks": checks,
            "platform": identity,
            "archive": {
                "name": archive_name,
                "sha256": sha256_file(first_path),
                "size_bytes": first_path.stat().st_size,
                "reproducible_sha256": sha256_file(second_path),
                "published_sha256": published,
            },
            "manifest": {
                "package_count": first_manifest["package_count"],
                "file_count": first_manifest["file_count"],
                "total_bytes": first_manifest["total_bytes"],
                "content_manifest_sha256": first_manifest["content_manifest_sha256"],
                "requirements_lock_sha256": first_manifest["requirements_lock_sha256"],
            },
            "restored": restored,
            "scope": "Linux CPython platform-specific installed-file snapshot",
            "limitations": [
                "the snapshot is not a package-index wheelhouse and does not provide upstream wheel signatures",
                "the snapshot is valid only for the recorded Linux, machine, Python ABI, and libc identity",
                "Windows and Python 3.12 runtime snapshots require separate builds and verification",
                "actual Docker image build and runtime remain unverified in this environment",
            ],
        }
    finally:
        if keep_workspace:
            print(f"workspace retained: {workspace}")
            workspace_obj.cleanup = lambda: None  # type: ignore[method-assign]
        else:
            workspace_obj.cleanup()


def _write_reports(payload: dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    archive = payload["archive"]
    manifest = payload["manifest"]
    restored = payload["restored"]
    lines = [
        f"VulnFlow {payload['version']} runtime dependency snapshot rehearsal",
        "",
        f"status: {'PASS' if payload['passed'] else 'FAIL'}",
        f"checks: {payload['checks_passed']}/{payload['checks_total']}",
        f"archive: {archive['name']}",
        f"archive_sha256: {archive['sha256']}",
        f"archive_size_bytes: {archive['size_bytes']}",
        f"packages: {manifest['package_count']}",
        f"files: {manifest['file_count']}",
        f"payload_bytes: {manifest['total_bytes']}",
        f"python_tag: {payload['platform']['python_tag']}",
        f"platform_tag: {payload['platform']['platform_tag']}",
        f"host_site_packages_bridge_absent: {restored['host_site_packages_absent']}",
        f"locked_packages_inside_clean_venv: {restored['all_locked_packages_inside_venv']}",
        f"locked_versions_match: {restored['all_locked_versions_match']}",
        f"live_status: {restored['live_status']}",
        f"ready_status: {restored['ready_status']}",
        f"anonymous_root_status: {restored['anonymous_root_status']}",
        f"authenticated_root_status: {restored['authenticated_root_status']}",
        f"shutdown_ms: {restored['shutdown_ms']}",
        f"schema_version: {restored['schema_version']}",
        f"sqlite_integrity: {restored['sqlite_integrity']}",
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
        print(
            f"runtime dependency snapshot: {payload['checks_passed']}/{payload['checks_total']} "
            f"archive={payload['archive']['name']}"
        )
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
