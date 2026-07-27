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

sys.dont_write_bytecode = True

BOOTSTRAP_FORMAT = "vulnflow-offline-deployment-bootstrap/1"
SNAPSHOT_PREFIX = "vulnflow-runtime-snapshot"
SNAPSHOT_FORMAT = "vulnflow-runtime-dependency-snapshot/1"
EXPECTED_SCHEMA_VERSION = 40


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or ".." in pure.parts or "\\" in name:
        raise ValueError(f"unsafe archive path: {name!r}")
    return pure


def _safe_extract_zip(path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("release kit contains duplicate ZIP entries")
        roots: set[str] = set()
        for info in infos:
            pure = _safe_relative(info.filename)
            roots.add(pure.parts[0])
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"release kit contains a symbolic link: {info.filename}")
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
            with archive.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
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


def inspect_snapshot(path: Path, expected_version: str) -> dict[str, Any]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if len(names) != len(set(names)):
            raise ValueError("runtime snapshot contains duplicate members")
        for member in members:
            _safe_relative(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"runtime snapshot contains an unsupported member: {member.name}")
        manifest_member = archive.getmember(f"{SNAPSHOT_PREFIX}/manifest.json")
        handle = archive.extractfile(manifest_member)
        if handle is None:
            raise ValueError("runtime snapshot manifest is unreadable")
        manifest = json.loads(handle.read().decode("utf-8"))
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
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"runtime snapshot member is unreadable: {relative}")
            data = source.read()
            if len(data) != int(item.get("size", -1)):
                raise ValueError(f"runtime snapshot size mismatch: {relative}")
            if _sha256_bytes(data) != str(item.get("sha256") or ""):
                raise ValueError(f"runtime snapshot digest mismatch: {relative}")
            total += len(data)
        if total != int(manifest.get("total_bytes", -1)):
            raise ValueError("runtime snapshot total byte count mismatch")
        return manifest


def restore_snapshot(path: Path, purelib: Path, expected_version: str) -> dict[str, Any]:
    manifest = inspect_snapshot(path, expected_version)
    restored = 0
    with tarfile.open(path, "r:gz") as archive:
        for item in manifest["files"]:
            relative = str(item["path"])
            pure = _safe_relative(relative)
            target = purelib.joinpath(*pure.parts)
            if target.exists() or target.is_symlink():
                raise ValueError(f"empty virtual environment contains a conflicting path: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(f"{SNAPSHOT_PREFIX}/site-packages/{relative}")
            if source is None:
                raise ValueError(f"runtime snapshot member is unreadable: {relative}")
            data = source.read()
            if _sha256_bytes(data) != item["sha256"]:
                raise ValueError(f"runtime snapshot changed during restore: {relative}")
            target.write_bytes(data)
            target.chmod(int(str(item.get("mode") or "0644"), 8))
            restored += 1
    return {"manifest": manifest, "restored_files": restored}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


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
            headers={"Authorization": _basic(credentials["admin_user"], credentials["admin_password"])},
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
        "admin_user": "vulnflow-admin",
        "admin_password": secrets.token_urlsafe(30),
        "api_token_name": "offline-bootstrap-operator",
        "api_token": secrets.token_urlsafe(36),
    }
    data = target / "data"
    for relative in ("", "evidence", "recovery", "exports", "tmp", "home", "cache"):
        path = data / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    config = {
        "HOME": str(data / "home"),
        "TMPDIR": str(data / "tmp"),
        "XDG_CACHE_HOME": str(data / "cache"),
        "VULNFLOW_HOST": "127.0.0.1",
        "VULNFLOW_PORT": "8000",
        "VULNFLOW_DB": str(data / "vulnflow.db"),
        "VULNFLOW_COORDINATION_DB": str(data / "vulnflow-coordination.db"),
        "VULNFLOW_EVIDENCE_DIR": str(data / "evidence"),
        "VULNFLOW_RECOVERY_DIR": str(data / "recovery"),
        "VULNFLOW_EXPORT_DIR": str(data / "exports"),
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK": "0",
        "VULNFLOW_USERS_JSON": json.dumps({credentials["admin_user"]: {"password": credentials["admin_password"], "role": "admin"}}, separators=(",", ":")),
        "VULNFLOW_API_TOKENS_JSON": json.dumps({credentials["api_token_name"]: {"token": credentials["api_token"], "role": "operator"}}, separators=(",", ":")),
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


def _write_launchers(target: Path, venv_python: Path, executable: Path, config_path: Path) -> None:
    bin_dir = target / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = bin_dir / "run_vulnflow.py"
    launcher.write_text(
        "from __future__ import annotations\n"
        "import json, os\n"
        "from pathlib import Path\n"
        f"config = json.loads(Path({str(config_path)!r}).read_text(encoding='utf-8'))\n"
        "os.environ.update({str(k): str(v) for k, v in config.items()})\n"
        "from app.cli import main\n"
        "main()\n",
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    run_sh = bin_dir / "run.sh"
    run_sh.write_text(f"#!/bin/sh\nset -eu\nexec {venv_python!s} {launcher!s}\n", encoding="utf-8")
    run_sh.chmod(0o700)
    verify_sh = bin_dir / "verify_installation.sh"
    verify_sh.write_text(
        "#!/bin/sh\nset -eu\n"
        f"{venv_python!s} -c \"import app, sqlite3; print('VulnFlow installation import: PASS')\"\n"
        f"test -x {executable!s}\n"
        "printf '%s\\n' 'VulnFlow console entry point: PASS'\n",
        encoding="utf-8",
    )
    verify_sh.chmod(0o700)


def deploy_release_kit(
    kit_zip: Path,
    target: Path,
    *,
    expected_kit_sha256: str,
    expected_public_key_fingerprint: str,
    expected_version: str,
    force: bool = False,
    run_cycles: int = 2,
) -> dict[str, Any]:
    if sys.platform != "linux" or sys.implementation.name != "cpython":
        raise RuntimeError("the bundled runtime snapshot currently supports Linux CPython only")
    if run_cycles < 2:
        raise ValueError("offline deployment rehearsal requires at least two cycles")
    kit_zip = kit_zip.resolve()
    expected_kit_sha256 = _validate_hex_digest(expected_kit_sha256, "expected release-kit SHA-256")
    actual_kit_sha256 = sha256_file(kit_zip)
    if actual_kit_sha256 != expected_kit_sha256:
        raise ValueError("release-kit SHA-256 does not match the out-of-band pinned value")
    expected_fingerprint = expected_public_key_fingerprint.strip().lower()
    if not expected_fingerprint.startswith("sha256:") or len(expected_fingerprint) != 71:
        raise ValueError("expected public-key fingerprint must use sha256:<64 hex> format")
    _validate_hex_digest(expected_fingerprint.split(":", 1)[1], "expected public-key fingerprint")

    if target.exists():
        if not force:
            raise FileExistsError(f"deployment target already exists: {target}")
        shutil.rmtree(target)
    target.mkdir(parents=True, mode=0o700)
    kit_dir = _safe_extract_zip(kit_zip, target / "release-kit")
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

    venv_root = target / "venv"
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

    config, credentials, credential_path = _secure_configuration(target, expected_version)
    _write_launchers(target, venv_python, executable, target / "config" / "runtime_environment.json")
    cycles: list[dict[str, Any]] = []
    for cycle in range(1, run_cycles + 1):
        cycles.append(
            _launch_cycle(
                executable,
                target,
                config,
                credentials,
                cycle,
                expect_persisted=(cycle > 1),
            )
        )
    database = Path(config["VULNFLOW_DB"])
    sqlite_state = _sqlite_state(database)
    checks = {
        "release_kit_sha256_pinned": actual_kit_sha256 == expected_kit_sha256,
        "release_public_key_pinned": actual_fingerprint == expected_fingerprint,
        "runtime_snapshot_integrity": restored["restored_files"] == int(snapshot_manifest["file_count"]),
        "signed_distribution_index_verified": True,
        "wheel_installed_offline": executable.is_file(),
        "private_runtime_configuration": (target / "config" / "runtime_environment.json").stat().st_mode & 0o077 == 0,
        "private_initial_credentials": credential_path.stat().st_mode & 0o077 == 0,
        "authentication_default_closed": all(item["anonymous_root_status"] == 401 for item in cycles),
        "authenticated_root_available": all(item["authenticated_root_status"] == 200 for item in cycles),
        "healthchecks_available": all(item["live_status"] == 200 and item["ready_status"] == 200 for item in cycles),
        "restart_persistence": cycles[-1]["persistence_verified"] is True,
        "sigterm_bounded": all(item["shutdown_ms"] <= 12_000 for item in cycles),
        "sqlite_integrity": sqlite_state["integrity"] == "ok",
        "sqlite_schema": sqlite_state["schema_version"] == EXPECTED_SCHEMA_VERSION,
        "bootstrap_finding_persisted": sqlite_state["bootstrap_findings"] == 1,
        "operator_launchers_created": (target / "bin" / "run.sh").is_file() and (target / "bin" / "verify_installation.sh").is_file(),
    }
    passed = sum(checks.values())
    report = {
        "format": BOOTSTRAP_FORMAT,
        "version": expected_version,
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "checks": [{"name": name, "passed": bool(value)} for name, value in checks.items()],
        "release_kit_sha256": actual_kit_sha256,
        "release_public_key_fingerprint": actual_fingerprint,
        "runtime_snapshot": {
            "file": snapshot.name,
            "sha256": sha256_file(snapshot),
            "packages": snapshot_manifest["package_count"],
            "files": snapshot_manifest["file_count"],
            "restored_files": restored["restored_files"],
            "platform": snapshot_manifest["platform"],
        },
        "wheel": {"file": wheel.name, "sha256": sha256_file(wheel)},
        "cycles": cycles,
        "sqlite": sqlite_state,
        "deployment_target": str(target),
        "credentials_file": str(credential_path),
        "run_command": str(target / "bin" / "run.sh"),
        "notice": "Initial credentials are stored only in the mode-0600 credentials file and are not included in this report.",
    }
    report_path = target / "OFFLINE_DEPLOYMENT_REPORT.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    report_path.chmod(0o600)
    if passed != len(checks):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError("offline deployment bootstrap checks failed: " + ", ".join(failed))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify and deploy VulnFlow from a signed offline release kit.")
    parser.add_argument("--release-kit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expected-kit-sha256", required=True)
    parser.add_argument("--expected-public-key-fingerprint", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--cycles", type=int, default=2)
    args = parser.parse_args()
    result = deploy_release_kit(
        Path(args.release_kit),
        Path(args.target),
        expected_kit_sha256=args.expected_kit_sha256,
        expected_public_key_fingerprint=args.expected_public_key_fingerprint,
        expected_version=args.expected_version,
        force=args.force,
        run_cycles=args.cycles,
    )
    print(
        f"VulnFlow {result['version']} offline deployment bootstrap: "
        f"{result['checks_passed']}/{result['checks_total']} PASS"
    )
    print(f"run: {result['run_command']}")
    print(f"initial credentials: {result['credentials_file']}")


if __name__ == "__main__":
    main()
