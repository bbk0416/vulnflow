from __future__ import annotations

"""Verify and deploy VulnFlow from a signed offline release kit.

The bootstrap intentionally starts with only Python's standard library. It
requires an out-of-band SHA-256 for the release-kit ZIP and an out-of-band
Ed25519 public-key fingerprint before extracting executable content. It then
restores the platform-specific runtime snapshot into an empty virtual
environment, verifies the signed release index, installs the VulnFlow wheel,
creates a private runtime configuration, and rehearses two bounded Uvicorn
cycles with SQLite persistence.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import shlex
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
import urllib.error
import urllib.request
import venv
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.offline_deployment_activation import (
        absolute_path,
        activate_staged_directory,
        deployment_operation_lock,
        remove_tree,
        rollback_activated_directory,
        sibling_staging_directory,
    )
    from scripts.offline_deployment_audit import append_deployment_audit_event
    from scripts.offline_deployment_history import (
        load_deployment_identity,
        prune_retained_deployments,
        seal_retained_deployment,
        write_deployment_identity,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import (
        absolute_path,
        activate_staged_directory,
        deployment_operation_lock,
        remove_tree,
        rollback_activated_directory,
        sibling_staging_directory,
    )
    from offline_deployment_audit import append_deployment_audit_event
    from offline_deployment_history import (
        load_deployment_identity,
        prune_retained_deployments,
        seal_retained_deployment,
        write_deployment_identity,
    )

sys.dont_write_bytecode = True

BOOTSTRAP_FORMAT = "vulnflow-offline-deployment-bootstrap/1"
SNAPSHOT_PREFIX = "vulnflow-runtime-snapshot"
SNAPSHOT_FORMAT = "vulnflow-runtime-dependency-snapshot/1"
MAX_RELEASE_KIT_ENTRIES = 4096
MAX_RELEASE_KIT_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_RELEASE_KIT_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_KIT_COMPRESSION_RATIO = 500
MAX_RUNTIME_SNAPSHOT_MEMBERS = 200_000
MAX_RUNTIME_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_RUNTIME_SNAPSHOT_MANIFEST_BYTES = 16 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


OFFLINE_MANAGEMENT_FILES = (
    "offline_deployment_activation.py",
    "offline_deployment_keyring.py",
    "offline_deployment_audit.py",
    "offline_deployment_witness.py",
    "offline_deployment_recovery.py",
    "offline_deployment_preflight.py",
    "offline_deployment_history.py",
    "offline_deployment_bootstrap.py",
    "manage_offline_deployments.py",
)


def _safe_relative(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or ".." in pure.parts or "\\" in name:
        raise ValueError(f"unsafe archive path: {name!r}")
    return pure


def _safe_extract_zip(path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if not infos:
            raise ValueError("release kit ZIP is empty")
        if len(infos) > MAX_RELEASE_KIT_ENTRIES:
            raise ValueError("release kit contains too many ZIP entries")
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("release kit contains duplicate ZIP entries")
        roots: set[str] = set()
        total_uncompressed = 0
        for info in infos:
            pure = _safe_relative(info.filename)
            roots.add(pure.parts[0])
            if info.flag_bits & 0x1:
                raise ValueError("release kit contains an encrypted ZIP entry")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"release kit contains a symbolic link: {info.filename}")
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError(f"release kit contains an unsupported ZIP entry: {info.filename}")
            if info.file_size < 0 or info.file_size > MAX_RELEASE_KIT_MEMBER_BYTES:
                raise ValueError(f"release kit member exceeds the size limit: {info.filename}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_RELEASE_KIT_UNCOMPRESSED_BYTES:
                raise ValueError("release kit exceeds the total uncompressed size limit")
            if info.file_size and info.compress_size == 0:
                raise ValueError(f"release kit member has an invalid compressed size: {info.filename}")
            if (
                info.compress_size > 0
                and info.file_size / info.compress_size > MAX_RELEASE_KIT_COMPRESSION_RATIO
            ):
                raise ValueError(f"release kit member exceeds the compression-ratio limit: {info.filename}")
        if len(roots) != 1:
            raise ValueError("release kit must contain exactly one top-level directory")
        root_name = next(iter(roots))
        destination.mkdir(parents=True, exist_ok=True)
        for info in infos:
            pure = _safe_relative(info.filename)
            target = destination.joinpath(*pure.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with archive.open(info) as source, target.open("wb") as output:
                while True:
                    chunk = source.read(min(1024 * 1024, info.file_size - copied + 1))
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > info.file_size or copied > MAX_RELEASE_KIT_MEMBER_BYTES:
                        raise ValueError(f"release kit member expanded beyond its declared size: {info.filename}")
                    output.write(chunk)
            if copied != info.file_size:
                raise ValueError(f"release kit member size changed during extraction: {info.filename}")
            target.chmod(0o644)
    return destination / root_name


def _decode_public_key(value: str) -> bytes:
    text = value.strip()
    try:
        raw = base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    except Exception as exc:
        raise ValueError("release public key is not URL-safe base64") from exc
    if len(raw) != 32:
        raise ValueError("release public key must decode to 32 bytes")
    return raw


def public_key_fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(_decode_public_key(value)).hexdigest()


def _validate_hex_digest(value: str, label: str) -> str:
    text = value.strip().lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest")
    return text


def _find_exactly_one(directory: Path, pattern: str, label: str) -> Path:
    matches = sorted(path for path in directory.glob(pattern) if path.is_file() and not path.is_symlink())
    if len(matches) != 1:
        raise ValueError(f"release kit must contain exactly one {label}; found {len(matches)}")
    return matches[0]


def _venv_paths(root: Path) -> tuple[Path, Path, Path]:
    if os.name == "nt":
        return root / "Scripts" / "python.exe", root / "Scripts", root / "Lib" / "site-packages"
    python = root / "bin" / "python"
    purelib = Path(
        subprocess.check_output(
            [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True,
        ).strip()
    )
    return python, root / "bin", purelib


def _stream_digest(source: Any, *, maximum_bytes: int, label: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise ValueError(f"{label} exceeds the permitted size")
        digest.update(chunk)
    return total, digest.hexdigest()


def inspect_snapshot(path: Path, expected_version: str) -> dict[str, Any]:
    with tarfile.open(path, "r:gz") as archive:
        members: list[tarfile.TarInfo] = []
        declared_bytes = 0
        for member in archive:
            members.append(member)
            if len(members) > MAX_RUNTIME_SNAPSHOT_MEMBERS:
                raise ValueError("runtime snapshot contains too many members")
            if member.isfile():
                if member.size < 0 or member.size > MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES:
                    raise ValueError(f"runtime snapshot member exceeds the size limit: {member.name}")
                declared_bytes += int(member.size)
                if declared_bytes > MAX_RUNTIME_SNAPSHOT_BYTES:
                    raise ValueError("runtime snapshot exceeds the uncompressed size limit")
        names = [item.name for item in members]
        if len(names) != len(set(names)):
            raise ValueError("runtime snapshot contains duplicate members")
        for member in members:
            _safe_relative(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"runtime snapshot contains an unsupported member: {member.name}")
        manifest_member = archive.getmember(f"{SNAPSHOT_PREFIX}/manifest.json")
        if manifest_member.size > MAX_RUNTIME_SNAPSHOT_MANIFEST_BYTES:
            raise ValueError("runtime snapshot manifest exceeds the size limit")
        handle = archive.extractfile(manifest_member)
        if handle is None:
            raise ValueError("runtime snapshot manifest is unreadable")
        manifest_bytes = handle.read(MAX_RUNTIME_SNAPSHOT_MANIFEST_BYTES + 1)
        if len(manifest_bytes) > MAX_RUNTIME_SNAPSHOT_MANIFEST_BYTES:
            raise ValueError("runtime snapshot manifest exceeds the size limit")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if manifest.get("format") != SNAPSHOT_FORMAT:
            raise ValueError("unexpected runtime snapshot format")
        if manifest.get("application_version") != expected_version:
            raise ValueError("runtime snapshot version mismatch")
        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            raise ValueError("runtime snapshot file manifest is empty")
        expected_names = {f"{SNAPSHOT_PREFIX}/site-packages/{item['path']}" for item in files}
        actual_names = {item.name for item in members if item.isfile() and item.name != manifest_member.name}
        if actual_names != expected_names:
            raise ValueError("runtime snapshot file set mismatch")
        total = 0
        for item in files:
            relative = str(item.get("path") or "")
            _safe_relative(relative)
            member = archive.getmember(f"{SNAPSHOT_PREFIX}/site-packages/{relative}")
            if member.size > MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES:
                raise ValueError(f"runtime snapshot member exceeds the size limit: {relative}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"runtime snapshot member is unreadable: {relative}")
            size, digest = _stream_digest(
                source,
                maximum_bytes=MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES,
                label=f"runtime snapshot member {relative}",
            )
            if size != int(item.get("size", -1)) or size != member.size:
                raise ValueError(f"runtime snapshot size mismatch: {relative}")
            if digest != str(item.get("sha256") or ""):
                raise ValueError(f"runtime snapshot digest mismatch: {relative}")
            total += size
            if total > MAX_RUNTIME_SNAPSHOT_BYTES:
                raise ValueError("runtime snapshot exceeds the uncompressed size limit")
        if total != int(manifest.get("total_bytes", -1)):
            raise ValueError("runtime snapshot total byte count mismatch")
        return manifest


def restore_snapshot(path: Path, purelib: Path, expected_version: str) -> dict[str, Any]:
    manifest = inspect_snapshot(path, expected_version)
    restored = 0
    restored_bytes = 0
    with tarfile.open(path, "r:gz") as archive:
        for item in manifest["files"]:
            relative = str(item["path"])
            pure = _safe_relative(relative)
            target = purelib.joinpath(*pure.parts)
            if target.exists() or target.is_symlink():
                raise ValueError(f"empty virtual environment contains a conflicting path: {relative}")
            expected_size = int(item["size"])
            if expected_size < 0 or expected_size > MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES:
                raise ValueError(f"runtime snapshot member exceeds the size limit: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(f"{SNAPSHOT_PREFIX}/site-packages/{relative}")
            if source is None:
                raise ValueError(f"runtime snapshot member is unreadable: {relative}")
            digest = hashlib.sha256()
            copied = 0
            try:
                with target.open("xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > expected_size or copied > MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES:
                            raise ValueError(f"runtime snapshot member expanded beyond its declared size: {relative}")
                        restored_bytes += len(chunk)
                        if restored_bytes > MAX_RUNTIME_SNAPSHOT_BYTES:
                            raise ValueError("runtime snapshot exceeds the uncompressed size limit")
                        digest.update(chunk)
                        output.write(chunk)
                if copied != expected_size:
                    raise ValueError(f"runtime snapshot size mismatch during restore: {relative}")
                if digest.hexdigest() != item["sha256"]:
                    raise ValueError(f"runtime snapshot changed during restore: {relative}")
                target.chmod(int(str(item.get("mode") or "0644"), 8))
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            restored += 1
    if restored_bytes != int(manifest.get("total_bytes", -1)):
        raise ValueError("runtime snapshot total byte count mismatch during restore")
    return {"manifest": manifest, "restored_files": restored}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 5,
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


def _multipart_csv(filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----VulnFlowBootstrap" + secrets.token_hex(12)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: text/csv\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


def _wait_ready(base_url: str, process: subprocess.Popen[Any], log_path: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"offline deployment process exited before readiness: {process.returncode}\n{log[-4000:]}")
        try:
            status, _ = _request(base_url + "/health/ready", timeout=1)
            if status == 200:
                return
            last = f"status={status}"
        except Exception as exc:
            last = str(exc)
        time.sleep(0.2)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"offline deployment process did not become ready ({last})\n{log[-4000:]}")


def _terminate(process: subprocess.Popen[Any], timeout: float = 12) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)
        raise RuntimeError("offline deployment process exceeded the SIGTERM deadline")


def _runtime_environment(config: dict[str, str]) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("VULNFLOW_")}
    env.update(config)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"})
    return env


def _launch_cycle(
    executable: Path,
    target: Path,
    config: dict[str, str],
    credentials: dict[str, str],
    cycle: int,
    *,
    expect_persisted: bool,
) -> dict[str, Any]:
    port = _free_port()
    local_config = dict(config)
    local_config["VULNFLOW_PORT"] = str(port)
    local_config["VULNFLOW_INSTANCE_ID"] = f"offline-bootstrap-{cycle}"
    log_path = target / "logs" / f"bootstrap-cycle-{cycle}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [str(executable)],
            cwd=target,
            env=_runtime_environment(local_config),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=(os.name == "posix"),
        )
    base_url = f"http://127.0.0.1:{port}"
    result: dict[str, Any] = {"cycle": cycle, "port": port}
    try:
        _wait_ready(base_url, process, log_path)
        result["live_status"] = _request(base_url + "/health/live")[0]
        result["ready_status"] = _request(base_url + "/health/ready")[0]
        result["anonymous_root_status"] = _request(base_url + "/")[0]
        result["authenticated_root_status"] = _request(
            base_url + "/",
            headers={"Authorization": f"Bearer {credentials['admin_api_token']}"},
        )[0]
        auth = {"Authorization": f"Bearer {credentials['api_token']}"}
        before, before_body = _request(base_url + "/api/v1/findings/OFFLINE-BOOTSTRAP-1", headers=auth)
        result["finding_before_status"] = before
        if expect_persisted:
            result["persistence_verified"] = before == 200 and b"offline-bootstrap" in before_body
        else:
            csv_data = b"finding_id,product,cve_id,cvss\nOFFLINE-BOOTSTRAP-1,Offline Bootstrap,CVE-2026-72010,8.8\n"
            body, content_type = _multipart_csv("offline-bootstrap.csv", csv_data)
            imported, _ = _request(
                base_url + "/api/v1/imports/csv?scanner_source=offline-bootstrap",
                method="POST",
                headers={**auth, "Content-Type": content_type},
                data=body,
                timeout=10,
            )
            after, after_body = _request(base_url + "/api/v1/findings/OFFLINE-BOOTSTRAP-1", headers=auth)
            result["import_status"] = imported
            result["finding_after_status"] = after
            result["persistence_verified"] = after == 200 and b"offline-bootstrap" in after_body
    finally:
        started = time.monotonic()
        result["return_code"] = _terminate(process)
        result["shutdown_ms"] = int((time.monotonic() - started) * 1000)
    result["log_tail"] = log_path.read_text(encoding="utf-8", errors="replace")[-1600:]
    return result


def _sqlite_state(database: Path) -> dict[str, Any]:
    with sqlite3.connect(database) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        schema = int(connection.execute("SELECT value FROM system_metadata WHERE key='schema_version'").fetchone()[0])
        findings = int(connection.execute("SELECT COUNT(*) FROM findings WHERE finding_id='OFFLINE-BOOTSTRAP-1'").fetchone()[0])
    return {"integrity": integrity, "schema_version": schema, "bootstrap_findings": findings}


def _write_private_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _secure_configuration(target: Path, version: str) -> tuple[dict[str, str], dict[str, str], Path]:
    credentials = {
        "admin_api_token_name": "offline-bootstrap-admin",
        "admin_api_token": secrets.token_urlsafe(36),
        "api_token_name": "offline-bootstrap-operator",
        "api_token": secrets.token_urlsafe(36),
    }
    data = target / "data"
    default_project = data / "projects" / "default"
    for path in (
        data,
        data / "tmp",
        data / "home",
        data / "cache",
        default_project / "evidence",
        default_project / "backups" / "recovery",
        default_project / "exports",
    ):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    config = {
        "HOME": str(data / "home"),
        "TMPDIR": str(data / "tmp"),
        "XDG_CACHE_HOME": str(data / "cache"),
        "VULNFLOW_HOST": "127.0.0.1",
        "VULNFLOW_PORT": "8000",
        "VULNFLOW_BASE_DIR": str(target),
        "VULNFLOW_DATA_DIR": str(data),
        "VULNFLOW_DB": str(data / "legacy-vulnflow.db"),
        "VULNFLOW_CONTROL_DB": str(data / "control.db"),
        "VULNFLOW_PROJECTS_DIR": str(data / "projects"),
        "VULNFLOW_DEFAULT_PROJECT_ROOT": str(default_project),
        "VULNFLOW_DEFAULT_PROJECT_DB": str(default_project / "vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(data / "vulnflow-coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(default_project / "evidence"),
        "VULNFLOW_RECOVERY_DIR": str(default_project / "backups" / "recovery"),
        "VULNFLOW_EXPORT_DIR": str(default_project / "exports"),
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
        "VULNFLOW_API_TOKENS_JSON": json.dumps({
            credentials["admin_api_token_name"]: {"token": credentials["admin_api_token"], "role": "admin", "projects": "*"},
            credentials["api_token_name"]: {"token": credentials["api_token"], "role": "operator", "projects": "*"},
        }, separators=(",", ":")),
        "VULNFLOW_CURSOR_SIGNING_KEY": secrets.token_urlsafe(48),
        "VULNFLOW_AUDIT_SIGNING_KEY": secrets.token_urlsafe(48),
        "VULNFLOW_BACKUP_SIGNING_KEY": secrets.token_urlsafe(48),
        "VULNFLOW_JOB_WORKER_ENABLED": "1",
        "VULNFLOW_JOB_WORKER_INTERVAL_SECONDS": "1",
        "VULNFLOW_MAINTENANCE_INTERVAL_MINUTES": "0",
        "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "1",
        "VULNFLOW_COOKIE_SECURE": "0",
        "VULNFLOW_LOG_LEVEL": "INFO",
    }
    config_path = target / "config" / "runtime_environment.json"
    credential_path = target / "config" / "INITIAL_CREDENTIALS.json"
    _write_private_json(config_path, config)
    _write_private_json(credential_path, credentials)
    return config, credentials, credential_path


def _install_management_tools(target: Path, kit_dir: Path) -> Path:
    destination = target / "bin" / "offline-management"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, mode=0o700)
    for name in OFFLINE_MANAGEMENT_FILES:
        source = kit_dir / name
        if source.is_symlink() or not source.is_file():
            raise FileNotFoundError(f"signed offline management artifact is missing: {name}")
        copied = destination / name
        shutil.copyfile(source, copied)
        if copied.read_bytes() != source.read_bytes():
            raise RuntimeError(f"offline management artifact copy mismatch: {name}")
        copied.chmod(0o600)
    return destination


def _write_launchers(
    target: Path,
    venv_python: Path,
    executable: Path,
    config_path: Path,
    management_dir: Path,
) -> None:
    bin_dir = target / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = bin_dir / "run_vulnflow.py"
    launcher.write_text(
        "from __future__ import annotations\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"config = json.loads(Path({str(config_path)!r}).read_text(encoding='utf-8'))\n"
        "os.environ.update({str(k): str(v) for k, v in config.items()})\n"
        f"management_dir = Path({str(management_dir)!r})\n"
        "if not management_dir.is_dir():\n"
        "    raise SystemExit('signed offline management tools are missing')\n"
        "sys.path.insert(0, str(management_dir))\n"
        "from offline_deployment_preflight import preflight_deployment_history\n"
        "preflight_deployment_history(Path(config['VULNFLOW_BASE_DIR']))\n"
        "from app.cli import main\n"
        "main()\n",
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    run_sh = bin_dir / "run.sh"
    run_sh.write_text(
        "#!/bin/sh\nset -eu\nexec "
        + shlex.quote(str(venv_python))
        + " "
        + shlex.quote(str(launcher))
        + "\n",
        encoding="utf-8",
    )
    run_sh.chmod(0o700)
    verify_sh = bin_dir / "verify_installation.sh"
    verify_sh.write_text(
        "#!/bin/sh\nset -eu\n"
        + shlex.quote(str(venv_python))
        + " -c "
        + shlex.quote("import app, sqlite3; print('VulnFlow installation import: PASS')")
        + "\n"
        + shlex.quote(str(venv_python))
        + " "
        + shlex.quote(str(management_dir / "offline_deployment_preflight.py"))
        + " --target "
        + shlex.quote(str(target))
        + " >/dev/null\n"
        + "test -x "
        + shlex.quote(str(executable))
        + "\n"
        + "printf '%s\\n' 'VulnFlow console entry point: PASS'\n",
        encoding="utf-8",
    )
    verify_sh.chmod(0o700)

def _relocate_runtime_configuration(target: Path, previous_root: Path) -> tuple[dict[str, str], dict[str, str], Path, Path]:
    config_path = target / "config" / "runtime_environment.json"
    credential_path = target / "config" / "INITIAL_CREDENTIALS.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    credentials = json.loads(credential_path.read_text(encoding="utf-8"))
    old_prefix = str(previous_root)
    new_prefix = str(target)
    relocated: dict[str, str] = {}
    for key, value in config.items():
        text = str(value)
        if text == old_prefix:
            text = new_prefix
        elif text.startswith(old_prefix + os.sep):
            text = new_prefix + text[len(old_prefix):]
        relocated[str(key)] = text
    _write_private_json(config_path, relocated)
    venv_python, venv_bin, _ = _venv_paths(target / "venv")
    executable = venv_bin / "vulnflow"
    if not executable.is_file():
        raise RuntimeError("activated VulnFlow console entry point is missing")
    _write_launchers(target, venv_python, executable, config_path, target / "bin" / "offline-management")
    return relocated, {str(k): str(v) for k, v in credentials.items()}, credential_path, executable


def _activation_verification(
    target: Path,
    previous_root: Path,
    *,
    expected_schema_version: int,
    run_cycles: int,
) -> dict[str, Any]:
    config, credentials, credential_path, executable = _relocate_runtime_configuration(target, previous_root)
    activation_cycle = _launch_cycle(
        executable,
        target,
        config,
        credentials,
        run_cycles + 1,
        expect_persisted=True,
    )
    database = Path(config["VULNFLOW_DEFAULT_PROJECT_DB"])
    sqlite_state = _sqlite_state(database)
    valid = (
        activation_cycle.get("live_status") == 200
        and activation_cycle.get("ready_status") == 200
        and activation_cycle.get("anonymous_root_status") == 401
        and activation_cycle.get("authenticated_root_status") == 200
        and activation_cycle.get("persistence_verified") is True
        and activation_cycle.get("return_code") == 0
        and int(activation_cycle.get("shutdown_ms", 99_999)) <= 12_000
        and sqlite_state["integrity"] == "ok"
        and sqlite_state["schema_version"] == expected_schema_version
        and sqlite_state["bootstrap_findings"] == 1
    )
    if not valid:
        raise RuntimeError(
            "activated offline deployment failed post-rename verification: "
            + json.dumps(
                {"cycle": activation_cycle, "sqlite": sqlite_state},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    return {
        "config": config,
        "credentials": credentials,
        "credentials_file": credential_path,
        "executable": executable,
        "activation_cycle": activation_cycle,
        "sqlite": sqlite_state,
    }


def _verified_release_schema(kit_dir: Path, expected_version: str) -> int:
    index_path = kit_dir / "release_distribution_index.json"
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    if str(payload.get("version") or "") != expected_version:
        raise ValueError("verified release index version mismatch")
    schema = payload.get("schemaVersion")
    if not isinstance(schema, int) or schema <= 0:
        raise ValueError("verified release index schemaVersion is invalid")
    return schema

def _deploy_release_kit_unlocked(
    kit_zip: Path,
    target: Path,
    *,
    expected_kit_sha256: str,
    expected_public_key_fingerprint: str,
    expected_version: str,
    force: bool = False,
    run_cycles: int = 2,
    retain_previous: int | None = 3,
) -> dict[str, Any]:
    if sys.platform != "linux" or sys.implementation.name != "cpython":
        raise RuntimeError("the bundled runtime snapshot currently supports Linux CPython only")
    if run_cycles < 2:
        raise ValueError("offline deployment rehearsal requires at least two cycles")
    kit_zip = kit_zip.resolve()
    target = absolute_path(target)
    if target == target.parent or str(target) in {"/", ""}:
        raise ValueError("refusing to deploy at the filesystem root")
    if os.path.lexists(target) and target.is_symlink():
        raise ValueError("deployment target must not be a symbolic link")
    if os.path.lexists(target) and not target.is_dir():
        raise ValueError("deployment target must be a directory")
    if os.path.lexists(target) and not force:
        raise FileExistsError(f"deployment target already exists: {target}")
    expected_kit_sha256 = _validate_hex_digest(expected_kit_sha256, "expected release-kit SHA-256")
    actual_kit_sha256 = sha256_file(kit_zip)
    if actual_kit_sha256 != expected_kit_sha256:
        raise ValueError("release-kit SHA-256 does not match the out-of-band pinned value")
    expected_fingerprint = expected_public_key_fingerprint.strip().lower()
    if not expected_fingerprint.startswith("sha256:") or len(expected_fingerprint) != 71:
        raise ValueError("expected public-key fingerprint must use sha256:<64 hex> format")
    _validate_hex_digest(expected_fingerprint.split(":", 1)[1], "expected public-key fingerprint")

    staging = sibling_staging_directory(target)
    activated = False
    try:
        kit_dir = _safe_extract_zip(kit_zip, staging / "release-kit")
        public_key_path = kit_dir / "release_distribution_public_key.txt"
        public_key = public_key_path.read_text(encoding="utf-8").strip()
        actual_fingerprint = public_key_fingerprint(public_key)
        if actual_fingerprint != expected_fingerprint:
            raise ValueError("release public key fingerprint does not match the out-of-band pinned value")

        snapshot = _find_exactly_one(kit_dir, f"vulnflow_runtime_dependencies-{expected_version}-*.tar.gz", "runtime snapshot")
        wheel = _find_exactly_one(kit_dir, f"bbk_vulnflow-{expected_version}-*.whl", "VulnFlow wheel")
        snapshot_manifest = inspect_snapshot(snapshot, expected_version)
        current_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
        if snapshot_manifest.get("platform", {}).get("python_tag") != current_tag:
            raise RuntimeError("runtime snapshot Python tag does not match the bootstrap interpreter")

        venv_root = staging / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_root)
        venv_python, venv_bin, purelib = _venv_paths(venv_root)
        restored = restore_snapshot(snapshot, purelib, expected_version)
        verifier = kit_dir / "verify_release_distribution.py"
        verify_result = subprocess.run(
            [
                str(venv_python), "-s", str(verifier),
                "--directory", str(kit_dir),
                "--expected-version", expected_version,
            ],
            check=False,
            timeout=120,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if verify_result.returncode != 0:
            raise RuntimeError("signed release distribution verification failed:\n" + verify_result.stdout[-4000:])
        expected_schema_version = _verified_release_schema(kit_dir, expected_version)
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--no-index", "--no-deps", "--force-reinstall", str(wheel)],
            check=True,
            timeout=120,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        executable = venv_bin / "vulnflow"
        if not executable.is_file():
            raise RuntimeError("installed VulnFlow console entry point is missing")

        config, credentials, credential_path = _secure_configuration(staging, expected_version)
        deployment_identity = write_deployment_identity(
            staging,
            application_version=expected_version,
            schema_version=expected_schema_version,
            release_kit_sha256=actual_kit_sha256,
            release_public_key_fingerprint=actual_fingerprint,
            target_name=target.name,
        )
        management_dir = _install_management_tools(staging, kit_dir)
        _write_launchers(staging, venv_python, executable, staging / "config" / "runtime_environment.json", management_dir)
        cycles: list[dict[str, Any]] = []
        for cycle in range(1, run_cycles + 1):
            cycles.append(
                _launch_cycle(
                    executable,
                    staging,
                    config,
                    credentials,
                    cycle,
                    expect_persisted=(cycle > 1),
                )
            )
        staged_database = Path(config["VULNFLOW_DEFAULT_PROJECT_DB"])
        staged_sqlite_state = _sqlite_state(staged_database)
        staged_checks = {
            "release_kit_sha256_pinned": actual_kit_sha256 == expected_kit_sha256,
            "release_public_key_pinned": actual_fingerprint == expected_fingerprint,
            "runtime_snapshot_integrity": restored["restored_files"] == int(snapshot_manifest["file_count"]),
            "signed_distribution_index_verified": True,
            "wheel_installed_offline": executable.is_file(),
            "private_runtime_configuration": (staging / "config" / "runtime_environment.json").stat().st_mode & 0o077 == 0,
            "private_initial_credentials": credential_path.stat().st_mode & 0o077 == 0,
            "authentication_default_closed": all(item["anonymous_root_status"] == 401 for item in cycles),
            "authenticated_root_available": all(item["authenticated_root_status"] == 200 for item in cycles),
            "healthchecks_available": all(item["live_status"] == 200 and item["ready_status"] == 200 for item in cycles),
            "restart_persistence": cycles[-1]["persistence_verified"] is True,
            "sigterm_bounded": all(item["shutdown_ms"] <= 12_000 for item in cycles),
            "sqlite_integrity": staged_sqlite_state["integrity"] == "ok",
            "sqlite_schema": staged_sqlite_state["schema_version"] == expected_schema_version,
            "bootstrap_finding_persisted": staged_sqlite_state["bootstrap_findings"] == 1,
            "operator_launchers_created": (staging / "bin" / "run.sh").is_file() and (staging / "bin" / "verify_installation.sh").is_file(),
            "deployment_identity_verified": load_deployment_identity(
                staging, expected_target_name=target.name
            ).installation_id == deployment_identity.installation_id,
        }
        if not all(staged_checks.values()):
            failed = [name for name, value in staged_checks.items() if not value]
            raise RuntimeError("offline deployment staging checks failed: " + ", ".join(failed))

        previous_root = staging
        activation = activate_staged_directory(
            staging,
            target,
            allow_replace=force,
            verify=lambda activated_target: _activation_verification(
                activated_target,
                previous_root,
                expected_schema_version=expected_schema_version,
                run_cycles=run_cycles,
            ),
        )
        activated = True
        final = activation.verification
        try:
            retained_seal = None
            if activation.previous_target is not None:
                retained_seal = seal_retained_deployment(target, activation.previous_target)
            checks = {
                **staged_checks,
                "atomic_activation_verified": True,
                "post_activation_healthchecks": final["activation_cycle"]["live_status"] == 200
                and final["activation_cycle"]["ready_status"] == 200,
                "post_activation_persistence": final["activation_cycle"]["persistence_verified"] is True,
                "post_activation_sqlite_integrity": final["sqlite"]["integrity"] == "ok",
                "post_activation_schema": final["sqlite"]["schema_version"] == expected_schema_version,
            }
            passed = sum(checks.values())
            retention: dict[str, Any] = {
                "enabled": retain_previous is not None,
                "keep": retain_previous,
                "status": "pending" if retain_previous is not None else "disabled",
                "removed": [],
                "unmanaged": [],
            }
            report = {
                "format": BOOTSTRAP_FORMAT,
                "version": expected_version,
                "deployment_identity": {
                    "installation_id": deployment_identity.installation_id,
                    "installed_at": deployment_identity.installed_at,
                    "schema_version": deployment_identity.schema_version,
                    "release_kit_sha256": deployment_identity.release_kit_sha256,
                    "release_public_key_fingerprint": deployment_identity.release_public_key_fingerprint,
                },
                "retention": retention,
                "checks_total": len(checks),
                "checks_passed": passed,
                "checks_failed": len(checks) - passed,
                "checks": [{"name": name, "passed": bool(value)} for name, value in checks.items()],
                "release_kit_sha256": actual_kit_sha256,
                "release_public_key_fingerprint": actual_fingerprint,
                "runtime_snapshot": {
                    "file": snapshot.name,
                    "sha256": sha256_file(target / "release-kit" / kit_dir.name / snapshot.name),
                    "packages": snapshot_manifest["package_count"],
                    "files": snapshot_manifest["file_count"],
                    "restored_files": restored["restored_files"],
                    "platform": snapshot_manifest["platform"],
                },
                "wheel": {
                    "file": wheel.name,
                    "sha256": sha256_file(target / "release-kit" / kit_dir.name / wheel.name),
                },
                "cycles": cycles,
                "activation_cycle": final["activation_cycle"],
                "sqlite": {**final["sqlite"], "expected_schema_version": expected_schema_version},
                "deployment_target": str(target),
                "previous_deployment": str(activation.previous_target) if activation.previous_target else None,
                "previous_deployment_seal": retained_seal,
                "credentials_file": str(final["credentials_file"]),
                "run_command": str(target / "bin" / "run.sh"),
                "notice": "Initial API tokens are stored only in the mode-0600 credentials file and are not included in this report.",
            }
            report_path = target / "OFFLINE_DEPLOYMENT_REPORT.json"
            report_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            report_path.chmod(0o600)
            if passed != len(checks):
                failed = [name for name, value in checks.items() if not value]
                raise RuntimeError("offline deployment bootstrap checks failed: " + ", ".join(failed))
            # Retention is intentionally post-commit.  A pruning or report-update
            # failure must never rollback a deployment after older trees were
            # irreversibly removed.
            if retain_previous is not None:
                try:
                    retention = {
                        "enabled": True,
                        "status": "completed",
                        **prune_retained_deployments(target, keep=int(retain_previous)),
                    }
                except Exception as exc:
                    retention = {
                        "enabled": True,
                        "status": "failed",
                        "keep": retain_previous,
                        "removed": [],
                        "unmanaged": [],
                        "error": str(exc),
                    }
                report["retention"] = retention
                try:
                    report_path.write_text(
                        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    report_path.chmod(0o600)
                except Exception as exc:
                    report["retention_report_error"] = str(exc)
            deployment_audit = append_deployment_audit_event(
                target,
                action="deployment_activated",
                details={
                    "installation_id": deployment_identity.installation_id,
                    "application_version": deployment_identity.application_version,
                    "schema_version": deployment_identity.schema_version,
                    "release_kit_sha256": actual_kit_sha256,
                    "previous_deployment": str(activation.previous_target) if activation.previous_target else None,
                },
            )
            report["deployment_audit"] = deployment_audit["audit"]
            return report
        except BaseException:
            rollback_activated_directory(target, activation.previous_target)
            activated = False
            raise
    finally:
        if not activated:
            remove_tree(staging)



def deploy_release_kit(
    kit_zip: Path,
    target: Path,
    *,
    expected_kit_sha256: str,
    expected_public_key_fingerprint: str,
    expected_version: str,
    force: bool = False,
    run_cycles: int = 2,
    retain_previous: int | None = 3,
) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        return _deploy_release_kit_unlocked(
            kit_zip,
            target,
            expected_kit_sha256=expected_kit_sha256,
            expected_public_key_fingerprint=expected_public_key_fingerprint,
            expected_version=expected_version,
            force=force,
            run_cycles=run_cycles,
            retain_previous=retain_previous,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify and deploy VulnFlow from a signed offline release kit.")
    parser.add_argument("--release-kit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expected-kit-sha256", required=True)
    parser.add_argument("--expected-public-key-fingerprint", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--retain-previous", type=int, default=3)
    args = parser.parse_args()
    result = deploy_release_kit(
        Path(args.release_kit),
        Path(args.target),
        expected_kit_sha256=args.expected_kit_sha256,
        expected_public_key_fingerprint=args.expected_public_key_fingerprint,
        expected_version=args.expected_version,
        force=args.force,
        run_cycles=args.cycles,
        retain_previous=args.retain_previous,
    )
    print(
        f"VulnFlow {result['version']} offline deployment bootstrap: "
        f"{result['checks_passed']}/{result['checks_total']} PASS"
    )
    print(f"run: {result['run_command']}")
    print(f"initial credentials: {result['credentials_file']}")


if __name__ == "__main__":
    main()
