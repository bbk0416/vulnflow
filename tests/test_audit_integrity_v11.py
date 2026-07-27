from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    add_audit_event,
    create_audit_checkpoint,
    init_db,
    list_audit_checkpoints,
    prune_audit_prefix,
    verify_audit_integrity,
)
from app.services.recovery import create_recovery_bundle, validate_recovery_bundle


def test_audit_chain_detects_direct_database_tampering(tmp_path: Path):
    db = tmp_path / "audit.sqlite3"
    init_db(db)
    add_audit_event(db, finding_id=None, event_type="one", summary="first", actor="tester")
    add_audit_event(db, finding_id="F-1", event_type="two", summary="second", actor="tester")
    assert verify_audit_integrity(db)["valid"] is True

    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER audit_events_immutable")
        conn.execute("UPDATE audit_events SET summary='tampered' WHERE chain_seq=1")
        conn.commit()

    result = verify_audit_integrity(db)
    assert result["valid"] is False
    assert any("event hash mismatch" in issue for issue in result["issues"])


def test_audit_events_are_immutable_through_application_schema(tmp_path: Path):
    db = tmp_path / "audit.sqlite3"
    init_db(db)
    add_audit_event(db, finding_id=None, event_type="one", summary="first")
    with sqlite3.connect(db) as conn, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE audit_events SET summary='changed' WHERE chain_seq=1")


def test_signed_checkpoint_verifies_and_wrong_key_is_rejected(tmp_path: Path):
    db = tmp_path / "audit.sqlite3"
    init_db(db)
    add_audit_event(db, finding_id=None, event_type="one", summary="first")
    checkpoint = create_audit_checkpoint(
        db, signing_key="correct-audit-signing-key", actor="admin"
    )
    assert checkpoint["signed"] is True
    assert list_audit_checkpoints(db)[0]["checkpoint_id"] == checkpoint["checkpoint_id"]
    assert verify_audit_integrity(db, signing_key="correct-audit-signing-key")["valid"] is True

    wrong = verify_audit_integrity(db, signing_key="wrong-audit-signing-key")
    assert wrong["valid"] is False
    assert wrong["checkpoints"][0]["signature_status"] == "invalid"


def test_contiguous_retention_prunes_prefix_and_preserves_chain(tmp_path: Path):
    db = tmp_path / "audit.sqlite3"
    init_db(db)
    add_audit_event(
        db, finding_id=None, event_type="old-1", summary="old 1",
        created_at="2020-01-01T00:00:00+00:00",
    )
    add_audit_event(
        db, finding_id=None, event_type="old-2", summary="old 2",
        created_at="2020-01-02T00:00:00+00:00",
    )
    add_audit_event(
        db, finding_id=None, event_type="current", summary="current",
        created_at="2026-07-20T00:00:00+00:00",
    )
    result = prune_audit_prefix(
        db,
        cutoff_at="2021-01-01T00:00:00+00:00",
        actor="maintenance",
        signing_key="audit-retention-signing-key",
    )
    assert result["deleted_count"] == 2
    assert result["anchor_seq"] == 2
    integrity = verify_audit_integrity(db, signing_key="audit-retention-signing-key")
    assert integrity["valid"] is True
    assert integrity["anchor_seq"] == 2
    assert integrity["checked_events"] == 2  # current + prune record
    assert integrity["checkpoints"][0]["signature_status"] == "valid"


def test_v10_database_migration_backfills_existing_audit_chain(tmp_path: Path):
    db = tmp_path / "legacy-v10.sqlite3"
    fixture = (Path(__file__).parent / "fixtures" / "v3_schema.sql").read_text(encoding="utf-8")
    with sqlite3.connect(db) as conn:
        conn.executescript(fixture)
        conn.execute(
            "INSERT INTO audit_events(finding_id,event_type,actor,summary,details_json,created_at) VALUES(NULL,'legacy','v10','first','{}','2026-01-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO audit_events(finding_id,event_type,actor,summary,details_json,created_at) VALUES(NULL,'legacy','v10','second','{}','2026-01-02T00:00:00+00:00')"
        )
        conn.execute("PRAGMA user_version=10")
        conn.commit()

    init_db(db)
    integrity = verify_audit_integrity(db)
    assert integrity["valid"] is True
    assert integrity["checked_events"] == 2
    assert integrity["last_seq"] == 2
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_recovery_bundle_rejects_rehashed_and_resigned_audit_tampering(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    bundle = tmp_path / "bundle.zip"
    tampered = tmp_path / "tampered.zip"
    backup_key = "backup-bundle-signing-key"
    audit_key = "audit-checkpoint-signing-key"
    init_db(db)
    add_audit_event(db, finding_id=None, event_type="one", summary="original")
    create_audit_checkpoint(db, signing_key=audit_key, actor="admin")
    create_recovery_bundle(
        db, bundle, signing_key=backup_key, audit_signing_key=audit_key,
        created_by="admin", base_dir=Path(__file__).resolve().parents[1],
    )
    assert validate_recovery_bundle(
        bundle, signing_key=backup_key, audit_signing_key=audit_key, require_signature=True,
    )["valid"] is True

    work = tmp_path / "bundle-work"
    work.mkdir()
    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(work)
    database = work / "database.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("DROP TRIGGER audit_events_immutable")
        conn.execute("UPDATE audit_events SET summary='tampered' WHERE chain_seq=1")
        conn.commit()

    manifest_path = work / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["database"]["sha256"] = _sha256(database)
    manifest_bytes = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)

    hashed = sorted(
        path for path in work.iterdir()
        if path.is_file() and path.name not in {"SHA256SUMS.txt", "manifest.hmac"}
    )
    sums_bytes = ("\n".join(f"{_sha256(path)}  {path.name}" for path in hashed) + "\n").encode("utf-8")
    (work / "SHA256SUMS.txt").write_bytes(sums_bytes)
    signature = hmac.new(backup_key.encode(), manifest_bytes + b"\n" + sums_bytes, hashlib.sha256).hexdigest()
    (work / "manifest.hmac").write_text(signature + "\n", encoding="ascii")
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(work.iterdir()):
            archive.write(path, arcname=path.name)

    with pytest.raises(ValueError, match="감사 체인"):
        validate_recovery_bundle(
            tampered, signing_key=backup_key, audit_signing_key=audit_key, require_signature=True,
        )
