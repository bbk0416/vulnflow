from __future__ import annotations

"""Rehearse the persisted Docker volume upgrade from 72.0.18/schema 42.

Host mode validates the exact database migration path without Docker.  Docker
mode additionally builds the current image, migrates a bind-mounted legacy
volume inside the image, starts Uvicorn, and checks the readiness endpoint.
"""

import argparse
import gzip
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import (  # noqa: E402
    CURRENT_APP_VERSION,
    CURRENT_SCHEMA_VERSION,
    get_schema_info,
    init_db,
)
from app.repositories.collaboration import get_integration, save_integration  # noqa: E402
from app.repositories.findings import get_finding  # noqa: E402
from app.services.integration_crypto import encrypt_secret  # noqa: E402

FIXTURE_ARCHIVE = ROOT / "tests" / "fixtures" / "v72_0_18_schema42.sqlite3.gz"
FIXTURE_META = ROOT / "tests" / "fixtures" / "v72_0_18_schema42_fixture.json"
TEST_MASTER_KEY = "vulnflow-container-upgrade-rehearsal-key-2026"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def materialize_fixture(destination: Path) -> dict[str, Any]:
    metadata = json.loads(FIXTURE_META.read_text(encoding="utf-8"))
    if _sha256(FIXTURE_ARCHIVE) != metadata["compressed_database_sha256"]:
        raise ValueError("schema 42 fixture compressed SHA-256 mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(FIXTURE_ARCHIVE, "rb") as source, destination.open("wb") as target:
        shutil.copyfileobj(source, target)
    if _sha256(destination) != metadata["uncompressed_database_sha256"]:
        raise ValueError("schema 42 fixture database SHA-256 mismatch")
    return metadata


def _table_exists(db_path: Path, table: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        return bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone())


def _check_current_database(db_path: Path, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: Any) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise AssertionError(f"{name}: {detail}")

    schema = get_schema_info(db_path)
    check(
        "schema migrated to current",
        schema["schema_version"] == CURRENT_SCHEMA_VERSION
        and schema["app_version"] == CURRENT_APP_VERSION,
        {"schema": schema["schema_version"], "app": schema["app_version"]},
    )
    for table, introduced in (
        ("collaboration_integrations", 43),
        ("collaboration_events", 43),
        ("finding_external_links", 43),
        ("pilot_project_profile", 44),
    ):
        check(f"schema {introduced} table {table}", _table_exists(db_path, table), table)
    finding = get_finding(db_path, str(metadata["finding_id"])) or {}
    check(
        "legacy finding preserved",
        finding.get("owner") == "legacy-team" and finding.get("status") == "IN_PROGRESS",
        {"finding_id": finding.get("finding_id"), "owner": finding.get("owner"), "status": finding.get("status")},
    )
    with sqlite3.connect(db_path) as conn:
        user = conn.execute(
            "SELECT username,role,is_active FROM app_users WHERE username=?",
            (metadata["username"],),
        ).fetchone()
        default_projects = int(conn.execute(
            "SELECT COUNT(*) FROM projects WHERE is_default=1 AND status='ACTIVE'"
        ).fetchone()[0])
    check("legacy administrator preserved", bool(user and user[1] == "admin" and int(user[2]) == 1), user)
    check("default project preserved", default_projects == 1, default_projects)

    secret = encrypt_secret({"api_token": "fixture-token-not-for-network"}, master_key=TEST_MASTER_KEY)
    save_integration(
        db_path,
        channel="JIRA",
        enabled=False,
        config={
            "base_url": "https://example.atlassian.net",
            "email": "fixture@example.com",
            "project_key": "SEC",
            "issue_type": "Task",
            "events": ["finding.workflow_changed"],
        },
        secret_ciphertext=secret,
        actor="upgrade-rehearsal",
    )
    integration = get_integration(db_path, "JIRA") or {}
    check(
        "post-upgrade collaboration write",
        integration.get("secret_configured") is True
        and integration.get("config", {}).get("project_key") == "SEC",
        {"secret_configured": integration.get("secret_configured"), "config": integration.get("config")},
    )
    return checks


def run_host_rehearsal(work_dir: Path) -> dict[str, Any]:
    database = work_dir / "data" / "vulnflow.db"
    metadata = materialize_fixture(database)
    with sqlite3.connect(database) as conn:
        before = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if before != 42:
        raise AssertionError(f"fixture schema must be 42, got {before}")
    init_db(database)
    checks = _check_current_database(database, metadata)
    return {
        "mode": "host",
        "passed": all(item["passed"] for item in checks),
        "source_release": metadata["source_release"],
        "source_schema_version": metadata["source_schema_version"],
        "target_release": CURRENT_APP_VERSION,
        "target_schema_version": CURRENT_SCHEMA_VERSION,
        "checks": checks,
        "database_sha256": _sha256(database),
    }


def _run(command: list[str], *, cwd: Path = ROOT, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout)


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise RuntimeError(f"{label} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")


def run_docker_rehearsal(work_dir: Path, *, image: str, build: bool = True) -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        raise FileNotFoundError("docker command not found")
    data_dir = work_dir / "docker-data"
    database = data_dir / "vulnflow.db"
    metadata = materialize_fixture(database)
    if build:
        _require_success(_run([docker, "build", "-t", image, "."], timeout=900), "docker build")

    mount = f"{data_dir.resolve()}:/app/data"
    ownership = _run([
        docker, "run", "--rm", "--user", "0", "-v", mount, image,
        "sh", "-c", "chown -R 10001:10001 /app/data",
    ], timeout=120)
    _require_success(ownership, "container data ownership preparation")
    migrate = _run([
        docker, "run", "--rm", "-v", mount,
        "-e", "VULNFLOW_CLUSTER_COORDINATION_ENABLED=0",
        image,
        "python", "-c",
        "from app.core.database_schema import init_db; init_db('/app/data/vulnflow.db')",
    ], timeout=300)
    _require_success(migrate, "container database migration")
    checks = _check_current_database(database, metadata)

    container_name = f"vulnflow-upgrade-rehearsal-{int(time.time())}"
    started = _run([
        docker, "run", "-d", "--name", container_name, "-v", mount,
        "-e", "VULNFLOW_CLUSTER_COORDINATION_ENABLED=0",
        "-e", "VULNFLOW_COOKIE_SECURE=0",
        image,
    ])
    _require_success(started, "container start")
    ready = False
    last_error = ""
    try:
        for _ in range(30):
            probe = _run([
                docker, "exec", container_name, "python", "-c",
                "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3).status)",
            ], timeout=10)
            if probe.returncode == 0 and "200" in probe.stdout:
                ready = True
                break
            last_error = (probe.stderr or probe.stdout).strip()[-500:]
            time.sleep(1)
    finally:
        _run([docker, "rm", "-f", container_name], timeout=60)
    checks.append({"name": "container readiness after upgrade", "passed": ready, "detail": last_error or "HTTP 200"})
    if not ready:
        raise AssertionError(f"container readiness failed: {last_error}")
    return {
        "mode": "docker",
        "passed": True,
        "image": image,
        "source_release": metadata["source_release"],
        "source_schema_version": metadata["source_schema_version"],
        "target_release": CURRENT_APP_VERSION,
        "target_schema_version": CURRENT_SCHEMA_VERSION,
        "checks": checks,
        "database_sha256": _sha256(database),
    }


def _text(result: dict[str, Any]) -> str:
    lines = [
        f"VulnFlow {result['target_release']} Docker volume upgrade rehearsal",
        f"mode: {result['mode']}",
        f"source: {result['source_release']} / schema {result['source_schema_version']}",
        f"target: {result['target_release']} / schema {result['target_schema_version']}",
        "",
    ]
    lines.extend(f"[{'PASS' if item['passed'] else 'FAIL'}] {item['name']}" for item in result["checks"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("auto", "host", "docker"), default="auto")
    parser.add_argument("--image", default=f"vulnflow:{CURRENT_APP_VERSION}-upgrade-rehearsal")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--require-docker", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="vulnflow_docker_upgrade_") as temporary:
        work_dir = args.work_dir or Path(temporary)
        work_dir.mkdir(parents=True, exist_ok=True)
        use_docker = args.mode == "docker" or (args.mode == "auto" and shutil.which("docker"))
        if args.require_docker and not shutil.which("docker"):
            print("Docker is required but not available.", file=sys.stderr)
            return 2
        try:
            if use_docker:
                result = run_docker_rehearsal(work_dir, image=args.image, build=not args.skip_build)
            else:
                result = run_host_rehearsal(work_dir)
                result["docker"] = "SKIPPED: docker command not found"
        except (AssertionError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f"upgrade rehearsal failed: {exc}", file=sys.stderr)
            return 1

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    print(_text(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
