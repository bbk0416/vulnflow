from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import apply_import_batch, get_finding, init_db
from app.services.recovery_mode import build_recovery_mode, recovery_write_allowed


def _settings(tmp_path: Path) -> dict[str, object]:
    default_root = tmp_path / "projects" / "default"
    return {
        "DATA_DIR": tmp_path,
        "LEGACY_DB_PATH": tmp_path / "legacy-vulnflow.db",
        "CONTROL_DB_PATH": tmp_path / "control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "PROJECTS_DIR": tmp_path / "projects",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "LEGACY_EVIDENCE_DIR": tmp_path / "legacy-evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "legacy-exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "legacy-previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "legacy-recovery",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "DEMO_MODE": True,
        "ALLOW_LOCAL_ADMIN_FALLBACK": True,
        "JOB_WORKER_ENABLED": True,
        "CLUSTER_COORDINATION_ENABLED": False,
        "MAINTENANCE_INTERVAL_MINUTES": 1,
        "BACKUP_INTERVAL_HOURS": 1,
    }


def _valid_evidence(*_args, **_kwargs):
    return {
        "valid": True,
        "artifact_count": 0,
        "invalid_count": 0,
        "unsafe_count": 0,
        "unexpected_file_count": 0,
        "issues": [],
    }


def _invalid_audit(*_args, **_kwargs):
    return {
        "valid": False,
        "issues": ["event 7 hash mismatch"],
        "last_seq": 7,
        "checkpoints": [],
    }


def test_recovery_policy_allows_only_safe_reads_and_repair_operations():
    assert recovery_write_allowed("GET", "/")
    assert recovery_write_allowed("POST", "/validate-recovery-bundle")
    assert recovery_write_allowed("POST", "/restore-recovery-bundle")
    assert recovery_write_allowed("POST", "/restore-backup")
    assert not recovery_write_allowed("POST", "/rescore")
    assert not recovery_write_allowed("DELETE", "/api/v1/findings/F-1")


def test_integrity_failure_starts_read_only_recovery_mode(tmp_path: Path):
    application = main.create_app(
        setting_overrides=_settings(tmp_path),
        service_overrides={
            "verify_evidence_store": _valid_evidence,
            "verify_audit_integrity": _invalid_audit,
        },
    )
    with TestClient(application) as client:
        context = application.state.vulnflow_context
        mode = context.get("RECOVERY_MODE")
        assert mode["active"] is True
        assert mode["read_only"] is True
        assert "감사 체인" in mode["reasons"][0]

        supervisor = context.get("LIFECYCLE_SUPERVISOR")
        assert supervisor.snapshot()["state"] == "NEW"
        assert supervisor.tasks == []

        live = client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["recovery_mode"] is True
        assert live.headers["x-vulnflow-recovery-mode"] == "active"

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "degraded"
        assert health.json()["recovery_mode"]["active"] is True

        ready = client.get("/health/ready")
        assert ready.status_code == 503
        assert "recovery mode" in ready.json()["detail"]

        home = client.get("/")
        assert home.status_code == 200
        assert "읽기 전용 복구 모드" in home.text

        blocked = client.post(
            "/rescore", data={"csrf_token": "invalid"}, headers={"Accept": "text/html"}
        )
        assert blocked.status_code == 503
        assert blocked.headers["x-vulnflow-recovery-mode"] == "active"
        assert "변경 요청이 차단" in blocked.text

        api_blocked = client.post("/api/v1/jobs", json={})
        assert api_blocked.status_code == 503
        assert api_blocked.json()["recovery_mode"]["active"] is True

        # Validation and restore endpoints pass the recovery-mode barrier and
        # reach their own CSRF/input validation instead of receiving 503.
        allowed = client.post("/validate-recovery-bundle")
        assert allowed.status_code != 503


def test_administrator_can_restore_known_good_sqlite_while_recovery_mode_is_active(
    tmp_path: Path,
):
    source = tmp_path / "known-good.sqlite3"
    init_db(source)
    apply_import_batch(
        source,
        [
            {
                "finding_id": "RECOVERY-RESTORED-1",
                "product": "Known Good",
                "asset_name": "restored-host",
                "cve_id": "CVE-2026-74001",
                "status": "OPEN",
                "scanner_source": "recovery-test",
                "record_state": "ACTIVE",
                "row_version": 1,
                "score": 70,
                "first_seen_at": "2026-08-01",
                "first_scored_at": "2026-08-01",
            }
        ],
        scanner_source="recovery-test",
        filename="known-good.csv",
    )

    target_dir = tmp_path / "target"
    target_dir.mkdir()
    application = main.create_app(
        setting_overrides=_settings(target_dir),
        service_overrides={
            "verify_evidence_store": _valid_evidence,
            "verify_audit_integrity": _invalid_audit,
        },
    )
    with TestClient(application) as client:
        page = client.get("/")
        csrf = page.cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
        response = client.post(
            "/restore-backup",
            data={"confirmation": "RESTORE", "csrf_token": csrf},
            files={
                "file": (
                    "known-good.sqlite3",
                    source.read_bytes(),
                    "application/vnd.sqlite3",
                )
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/?notice=restore_ok"
        restored = get_finding(
            Path(application.state.vulnflow_context.get("DEFAULT_PROJECT_DB_PATH")),
            "RECOVERY-RESTORED-1",
        )
        assert restored is not None
        assert restored["asset_name"] == "restored-host"
        # Startup integrity state is intentionally re-evaluated only on restart.
        mode = application.state.vulnflow_context.get("RECOVERY_MODE")
        assert mode["active"] is True


def test_integrity_check_exception_is_converted_to_recovery_diagnostic(tmp_path: Path):
    def broken_evidence(*_args, **_kwargs):
        raise OSError("storage temporarily unavailable")

    application = main.create_app(
        setting_overrides=_settings(tmp_path),
        service_overrides={
            "verify_evidence_store": broken_evidence,
            "verify_audit_integrity": lambda *_a, **_k: {
                "valid": True,
                "issues": [],
                "last_seq": 0,
                "checkpoints": [],
            },
        },
    )
    with TestClient(application):
        mode = application.state.vulnflow_context.get("RECOVERY_MODE")
        assert mode["active"] is True
        assert mode["evidence_integrity"]["error_type"] == "OSError"
        assert "검사 실행 실패" in mode["reasons"][0]


def test_recovery_mode_summary_preserves_both_failures():
    mode = build_recovery_mode(
        evidence_integrity={"valid": False, "issues": ["unexpected file"]},
        audit_integrity={"valid": False, "issues": ["hash mismatch"]},
    )
    assert mode["active"] is True
    assert len(mode["reasons"]) == 2
    assert mode["allowed_write_paths"] == sorted(mode["allowed_write_paths"])
