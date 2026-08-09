from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.services.database_lifecycle import backup_database
from scripts.local_tls_certificate import generate_self_signed_certificate
from scripts import production_compose_rehearsal
from scripts.smtp_egress_rehearsal import _certificate as smtp_certificate

ROOT = Path(__file__).resolve().parents[1]


def _database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample(value) VALUES ('windows-portability')")
        connection.commit()


def test_backup_database_publishes_a_valid_snapshot_with_a_writable_fsync_descriptor(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    _database(source)

    backup_database(source, destination)

    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == (
            "windows-portability",
        )


def test_local_tls_certificate_is_parseable_and_contains_requested_san(tmp_path: Path) -> None:
    certificate_path, key_path = generate_self_signed_certificate(
        tmp_path,
        common_name="localhost",
        dns_names=("localhost",),
        ip_addresses=("127.0.0.1",),
    )

    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    assert "127.0.0.1" in {str(value) for value in san.get_values_for_type(x509.IPAddress)}
    assert private_key.key_size == 2048


def test_smtp_rehearsal_certificate_no_longer_needs_an_openssl_executable(
    tmp_path: Path,
) -> None:
    certificate_path, key_path = smtp_certificate(tmp_path)
    assert certificate_path.is_file()
    assert key_path.is_file()
    assert b"BEGIN CERTIFICATE" in certificate_path.read_bytes()
    assert b"BEGIN RSA PRIVATE KEY" in key_path.read_bytes()


def test_compose_rehearsal_uses_cross_platform_long_bind_mount_syntax(tmp_path: Path) -> None:
    compose = production_compose_rehearsal.build_rehearsal_compose(
        ROOT,
        certificate_directory=tmp_path,
        http_port=18080,
        https_port=18443,
        image="vulnflow:test",
    )
    volumes = compose["services"]["proxy"]["volumes"]
    assert all(item["type"] == "bind" for item in volumes)
    assert all(item["read_only"] is True for item in volumes)
    assert {item["target"] for item in volumes} == {
        "/etc/nginx/conf.d/default.conf",
        "/etc/nginx/certs",
    }


def test_compose_rehearsal_failure_still_writes_a_machine_readable_report(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "compose-report.json"

    def fail(*, require_docker: bool = False):
        raise RuntimeError("simulated compose failure")

    monkeypatch.setattr(production_compose_rehearsal, "run_rehearsal", fail)
    monkeypatch.setattr(production_compose_rehearsal.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(sys, "argv", ["production_compose_rehearsal.py", "--json-output", str(output)])

    assert production_compose_rehearsal.main() == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["passed"] is False
    assert report["available"] is True
    assert report["error_type"] == "RuntimeError"


def test_runtime_lock_contains_the_windows_dependency_closure_pin() -> None:
    assert "idna==3.17" in (ROOT / "requirements.lock").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "app/resources/runtime_dependency_lock.json").read_text(encoding="utf-8")
    )
    assert any(
        item["name"] == "idna" and item["version"] == "3.17"
        for item in manifest["packages"]
    )


def test_posix_only_offline_deployment_tests_use_selective_windows_skips() -> None:
    decorated = 0
    for version in range(95, 105):
        matches = list((ROOT / "tests").glob(f"test_offline_deployment_*_v{version}.py"))
        assert len(matches) == 1, version
        source = matches[0].read_text(encoding="utf-8")
        assert "pytestmark = pytest.mark.skipif" not in source
        decorated += source.count("Windows validation: POSIX filesystem semantics")
    assert decorated == 74


def test_browser_e2e_uses_a_unique_locator_and_a_file_backed_server_log() -> None:
    source = (ROOT / "tests/e2e/test_vm_workflows.py").read_text(encoding="utf-8")
    assert "a.finding-link[href='/finding/F-0001']" in source
    assert "stdout=subprocess.PIPE" not in source
    assert "uvicorn-e2e.log" in source
