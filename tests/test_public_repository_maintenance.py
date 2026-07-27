from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys

import pytest
from pathlib import Path

import app.services.database_lifecycle as database_lifecycle
from app.core.db import connect
from app.core.storage import init_db

ROOT = Path(__file__).resolve().parents[1]


def _run(*parts: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *parts], cwd=ROOT, text=True, capture_output=True)


def test_architecture_review_creates_missing_report_directory(tmp_path: Path) -> None:
    reports = ROOT / "reports"
    shutil.rmtree(reports, ignore_errors=True)
    result = _run("scripts/architecture_review.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (reports / "architecture_review.txt").is_file()
    assert (reports / "architecture_review.json").is_file()


def test_public_submission_readiness_is_self_contained() -> None:
    result = _run("scripts/submission_readiness_smoke.py", "--public")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "public submission readiness verification" in result.stdout


def test_public_manifest_verifier_accepts_repository_manifest() -> None:
    result = _run("scripts/verify_public_manifest.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verification: PASS" in result.stdout


def test_database_validation_closes_sqlite_connection(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "validated.sqlite3"
    init_db(database)
    original_connect = database_lifecycle.sqlite3.connect
    tracked: list[object] = []

    class ConnectionProxy:
        def __init__(self, connection):
            self._connection = connection
            self.closed = False

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def close(self):
            self.closed = True
            return self._connection.close()

    def tracked_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        if not kwargs.get("uri"):
            return connection
        proxy = ConnectionProxy(connection)
        tracked.append(proxy)
        return proxy

    monkeypatch.setattr(database_lifecycle.sqlite3, "connect", tracked_connect)
    summary = database_lifecycle.validate_database_file(database)
    assert summary["schema_version"] >= 1
    assert tracked
    assert all(item.closed for item in tracked)


def test_connect_context_manager_closes_database_handle(tmp_path: Path) -> None:
    database = tmp_path / "context.sqlite3"
    init_db(database)
    with connect(database) as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_clamscan_signature_parser_ignores_windows_drive_colon(tmp_path: Path, monkeypatch) -> None:
    from app.services import evidence as evidence_service

    scanner = tmp_path / "fake-clamscan.exe"
    scanner.write_bytes(b"placeholder")
    evidence = tmp_path / "infected.txt"
    evidence.write_text("sample", encoding="utf-8")

    def fake_run(command, **kwargs):
        output = f"C:\\Temp\\infected.txt: Unit.Test FOUND\n"
        return subprocess.CompletedProcess(command, 1, stdout=output, stderr="")

    monkeypatch.setattr(evidence_service.subprocess, "run", fake_run)
    result = evidence_service.scan_evidence_path(
        evidence, mode="clamscan", clamscan_path=str(scanner)
    )
    assert result["scan_status"] == "INFECTED"
    assert result["scan_signature"] == "Unit.Test"
