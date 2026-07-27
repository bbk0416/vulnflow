from __future__ import annotations

import hashlib
import hmac
import json
from importlib import metadata
import os
import shutil
import tempfile
import zipfile
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from app.core.signing import KEY_ID_RE, build_signing_config, hmac_sha256, verify_hmac
from app.core.public_signing import build_ed25519_signing_config
from app.services.evidence import verify_evidence_custody_chain
from app.core.database_schema import get_schema_info
from app.core.db import connect
from app.repositories.audit import verify_audit_integrity
from app.services.database_lifecycle import backup_database, restore_database, validate_database_file

RECOVERY_FORMAT = "vulnflow-recovery/1"
MAX_BUNDLE_FILES = 2048
MAX_BUNDLE_UNCOMPRESSED = 1024 * 1024 * 1024
REQUIRED_FILES = {"manifest.json", "database.sqlite3", "config-audit.json", "audit-integrity.json", "SHA256SUMS.txt"}
EVIDENCE_MANIFEST_FORMAT = "vulnflow-evidence/1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _app_version(base_dir: str | Path | None = None) -> str:
    root = Path(base_dir) if base_dir else Path(__file__).resolve().parents[2]
    version_file = root / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    try:
        return metadata.version("bbk-vulnflow")
    except metadata.PackageNotFoundError:
        return "unknown"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_object(value: str) -> dict[str, Any]:
    if not str(value or "").strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def build_config_audit(
    env: Mapping[str, str] | None = None,
    *,
    db_path: str | Path | None = None,
    base_dir: str | Path | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Return a redacted configuration posture report. Secrets and full webhook URLs are never included."""
    values = dict(os.environ if env is None else env)
    users = _json_object(values.get("VULNFLOW_USERS_JSON", ""))
    tokens = _json_object(values.get("VULNFLOW_API_TOKENS_JSON", ""))
    webhooks = _json_object(values.get("VULNFLOW_WEBHOOKS_JSON", ""))
    legacy_auth = bool(values.get("VULNFLOW_AUTH_USER", "") or values.get("VULNFLOW_AUTH_PASSWORD", ""))
    auth_configured = bool(users or tokens or legacy_auth)

    def as_bool(name: str, default: bool = False) -> bool:
        raw = str(values.get(name, "1" if default else "0")).strip().lower()
        return raw in {"1", "true", "yes", "on"}

    def as_int(name: str, default: int = 0) -> int:
        try:
            return int(str(values.get(name, str(default))) or default)
        except (TypeError, ValueError):
            return default

    signing_config_error = ""
    try:
        signing_config = build_signing_config(
            signing_keys_json=str(values.get("VULNFLOW_SIGNING_KEYS_JSON", "")),
            audit_active_key_id=str(values.get("VULNFLOW_AUDIT_ACTIVE_KEY_ID", "")),
            backup_active_key_id=str(values.get("VULNFLOW_BACKUP_ACTIVE_KEY_ID", "")),
            legacy_audit_key=str(values.get("VULNFLOW_AUDIT_SIGNING_KEY", "")),
            legacy_backup_key=str(values.get("VULNFLOW_BACKUP_SIGNING_KEY", "")),
            require_audit=as_bool("VULNFLOW_AUDIT_REQUIRE_SIGNATURE"),
            require_backup=as_bool("VULNFLOW_BACKUP_REQUIRE_SIGNATURE"),
        )
    except ValueError as exc:
        signing_config_error = str(exc)
        signing_config = build_signing_config()

    proof_signing_config_error = ""
    try:
        proof_signing_config = build_ed25519_signing_config(
            private_keys_json=str(values.get("VULNFLOW_INTEGRITY_PROOF_PRIVATE_KEYS_JSON", "")),
            public_keys_json=str(values.get("VULNFLOW_INTEGRITY_PROOF_PUBLIC_KEYS_JSON", "")),
            active_key_id=str(values.get("VULNFLOW_INTEGRITY_PROOF_ACTIVE_KEY_ID", "")),
            require_private=as_bool("VULNFLOW_INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE"),
        )
    except ValueError as exc:
        proof_signing_config_error = str(exc)
        proof_signing_config = build_ed25519_signing_config()

    mirror_signing_config_error = ""
    try:
        mirror_signing_config = build_ed25519_signing_config(
            private_keys_json=str(values.get("VULNFLOW_INTEGRITY_MIRROR_PRIVATE_KEYS_JSON", "")),
            public_keys_json=str(values.get("VULNFLOW_INTEGRITY_MIRROR_PUBLIC_KEYS_JSON", "")),
            active_key_id=str(values.get("VULNFLOW_INTEGRITY_MIRROR_ACTIVE_KEY_ID", "")),
            require_private=as_bool("VULNFLOW_INTEGRITY_MIRROR_REQUIRE_GOSSIP"),
        )
    except ValueError as exc:
        mirror_signing_config_error = str(exc)
        mirror_signing_config = build_ed25519_signing_config()

    webhook_summary: list[dict[str, Any]] = []
    for name, item in sorted(webhooks.items()):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        scheme = url.split(":", 1)[0].lower() if ":" in url else "unknown"
        events = item.get("events") if isinstance(item.get("events"), list) else []
        webhook_summary.append({"name": str(name), "scheme": scheme, "event_count": len(events)})

    settings = {
        "app_version": _app_version(base_dir),
        "authentication": {
            "configured": auth_configured,
            "local_fallback_enabled": not auth_configured,
            "basic_user_count": len(users) + (1 if legacy_auth else 0),
            "api_token_count": len(tokens),
        },
        "cookies": {"secure": as_bool("VULNFLOW_COOKIE_SECURE")},
        "workers": {
            "enabled": as_bool("VULNFLOW_JOB_WORKER_ENABLED", True),
            "lease_seconds": as_int("VULNFLOW_JOB_LEASE_SECONDS", 120),
            "max_attempts": as_int("VULNFLOW_JOB_MAX_ATTEMPTS", 3),
        },
        "cluster_coordination": {
            "enabled": as_bool("VULNFLOW_CLUSTER_COORDINATION_ENABLED", True),
            "coordination_filename": Path(values.get("VULNFLOW_COORDINATION_DB") or "vulnflow-coordination.db").name,
            "heartbeat_seconds": as_int("VULNFLOW_INSTANCE_HEARTBEAT_SECONDS", 10),
            "instance_ttl_seconds": as_int("VULNFLOW_INSTANCE_TTL_SECONDS", 30),
            "scheduler_lease_seconds": as_int("VULNFLOW_SCHEDULER_LEASE_SECONDS", 30),
            "exclusive_operation_lease_seconds": as_int("VULNFLOW_EXCLUSIVE_OPERATION_LEASE_SECONDS", 300),
            "write_activity_ttl_seconds": as_int("VULNFLOW_WRITE_ACTIVITY_TTL_SECONDS", 600),
        },
        "maintenance": {
            "interval_minutes": as_int("VULNFLOW_MAINTENANCE_INTERVAL_MINUTES", 0),
            "audit_retention_days": as_int("VULNFLOW_AUDIT_RETENTION_DAYS", 0),
            "import_retention_days": as_int("VULNFLOW_IMPORT_RETENTION_DAYS", 0),
            "job_retention_days": as_int("VULNFLOW_JOB_RETENTION_DAYS", 30),
            "idempotency_retention_days": as_int("VULNFLOW_IDEMPOTENCY_RETENTION_DAYS", 30),
            "execution_receipt_retention_days": as_int("VULNFLOW_EXECUTION_RECEIPT_RETENTION_DAYS", 180),
            "webhook_retention_days": as_int("VULNFLOW_WEBHOOK_RETENTION_DAYS", 0),
        },
        "export_storage": {
            "directory_name": Path(values.get("VULNFLOW_EXPORT_DIR") or "exports").name,
            "retention_days": as_int("VULNFLOW_EXPORT_RETENTION_DAYS", 7),
            "quota_mb": as_int("VULNFLOW_EXPORT_QUOTA_MB", 1024),
            "minimum_free_mb": as_int("VULNFLOW_EXPORT_MIN_FREE_MB", 256),
            "pinned_artifacts_supported": True,
            "lru_eviction_enabled": True,
        },
        "signing_keys": signing_config.public_summary() | {"configuration_error": signing_config_error or None},
        "integrity_proof_public_signing": proof_signing_config.public_summary() | {
            "configuration_error": proof_signing_config_error or None,
            "public_signature_required": as_bool("VULNFLOW_INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE"),
        },
        "integrity_proof_mirror_gossip": mirror_signing_config.public_summary() | {
            "configuration_error": mirror_signing_config_error or None,
            "gossip_required": as_bool("VULNFLOW_INTEGRITY_MIRROR_REQUIRE_GOSSIP"),
            "minimum_quorum": max(1, min(32, as_int("VULNFLOW_INTEGRITY_MIRROR_MIN_QUORUM", 1))),
            "role_separation_required": True,
        },
        "audit_integrity": {
            "signing_configured": bool(signing_config.audit_active_key_id),
            "active_key_id": signing_config.audit_active_key_id,
            "signature_required": as_bool("VULNFLOW_AUDIT_REQUIRE_SIGNATURE"),
        },
        "evidence_store": {
            "directory_name": Path(values.get("VULNFLOW_EVIDENCE_DIR") or "evidence").name,
            "max_upload_bytes": as_int("VULNFLOW_EVIDENCE_MAX_BYTES", 10 * 1024 * 1024),
            "included_in_recovery_bundle": True,
            "scanner_mode": str(values.get("VULNFLOW_EVIDENCE_SCANNER_MODE", "builtin") or "builtin").lower(),
            "clean_required": as_bool("VULNFLOW_EVIDENCE_REQUIRE_CLEAN", True),
            "chain_of_custody_enabled": True,
            "provenance_immutable": True,
        },
        "recovery": {
            "scheduled_interval_hours": as_int("VULNFLOW_BACKUP_INTERVAL_HOURS", 0),
            "retention_count": as_int("VULNFLOW_BACKUP_RETENTION_COUNT", 10),
            "bundle_signing_configured": bool(signing_config.backup_active_key_id),
            "active_key_id": signing_config.backup_active_key_id,
            "restore_signature_required": as_bool("VULNFLOW_BACKUP_REQUIRE_SIGNATURE"),
        },
        "webhooks": {
            "configured_count": len(webhook_summary),
            "allow_insecure_http": as_bool("VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP"),
            "endpoints": webhook_summary,
        },
        "supply_chain_intelligence": {
            "provider": "OSV.dev",
            "api_scheme": str(values.get("VULNFLOW_OSV_API_BASE", "https://api.osv.dev")).split(":", 1)[0].lower(),
            "timeout_seconds": as_int("VULNFLOW_OSV_TIMEOUT_SECONDS", 15),
            "retries": as_int("VULNFLOW_OSV_RETRIES", 3),
            "batch_size": as_int("VULNFLOW_OSV_BATCH_SIZE", 100),
            "candidate_review_required": True,
        },
        "pagination": {
            "cursor_signing_key_configured": bool(str(values.get("VULNFLOW_CURSOR_SIGNING_KEY", "")).strip()),
            "cursor_hmac_enabled": True,
            "fts5_search_enabled": True,
        },
        "database": {
            "filename": Path(db_path).name if db_path else "vulnflow.db",
            "wal_enabled_by_application": True,
        },
    }

    findings: list[dict[str, str]] = []

    def warning(code: str, severity: str, message: str) -> None:
        findings.append({"code": code, "severity": severity, "message": message})

    if not auth_configured:
        warning("AUTH_LOCAL_FALLBACK", "HIGH", "인증 설정이 없어 루프백 로컬 관리자 fallback이 활성화됩니다.")
    if auth_configured and not settings["cookies"]["secure"]:
        warning("COOKIE_NOT_SECURE", "MEDIUM", "인증 사용 중 Secure 쿠키가 비활성화되어 있습니다.")
    if not settings["workers"]["enabled"]:
        warning("JOB_WORKER_DISABLED", "HIGH", "백그라운드 워커가 비활성화되어 영속 작업이 실행되지 않습니다.")
    cluster = settings["cluster_coordination"]
    if not cluster["enabled"]:
        warning("CLUSTER_COORDINATION_DISABLED", "MEDIUM", "다중 프로세스 리더 선출과 복원 쓰기 차단이 비활성화되어 있습니다.")
    if cluster["instance_ttl_seconds"] < cluster["heartbeat_seconds"] * 2:
        warning("CLUSTER_TTL_TOO_SHORT", "HIGH", "인스턴스 TTL은 하트비트 주기의 2배 이상이어야 합니다.")
    if cluster["scheduler_lease_seconds"] < cluster["heartbeat_seconds"] * 2:
        warning("SCHEDULER_LEASE_TOO_SHORT", "HIGH", "스케줄러 임대는 하트비트 주기의 2배 이상이어야 합니다.")
    if settings["webhooks"]["allow_insecure_http"]:
        warning("INSECURE_WEBHOOK_HTTP", "HIGH", "원격 평문 HTTP 웹훅이 허용되어 있습니다.")
    if signing_config_error:
        warning("SIGNING_KEYRING_INVALID", "HIGH", signing_config_error)
    if proof_signing_config_error:
        warning("INTEGRITY_PROOF_PUBLIC_SIGNING_INVALID", "HIGH", proof_signing_config_error)
    if mirror_signing_config_error:
        warning("INTEGRITY_PROOF_MIRROR_SIGNING_INVALID", "HIGH", mirror_signing_config_error)
    mirror_settings = settings["integrity_proof_mirror_gossip"]
    if mirror_settings["gossip_required"] and not mirror_signing_config.active_key_id:
        warning(
            "INTEGRITY_PROOF_MIRROR_GOSSIP_REQUIRED", "HIGH",
            "Mirror gossip 필수 모드에는 활성 Ed25519 mirror signing key가 필요합니다.",
        )
    if mirror_settings["gossip_required"] and len(mirror_signing_config.public_keys) < mirror_settings["minimum_quorum"]:
        warning(
            "INTEGRITY_PROOF_MIRROR_QUORUM_UNAVAILABLE", "HIGH",
            "설정된 mirror 공개키 수가 최소 quorum보다 적습니다.",
        )
    if as_bool("VULNFLOW_INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE") and not proof_signing_config.active_key_id:
        warning(
            "INTEGRITY_PROOF_PUBLIC_SIGNING_REQUIRED", "HIGH",
            "공개 검증 필수 모드에는 활성 Ed25519 proof signing key가 필요합니다.",
        )
    if not settings["recovery"]["bundle_signing_configured"]:
        warning("BACKUP_UNSIGNED", "MEDIUM", "복구 번들 활성 HMAC 서명 키가 설정되지 않았습니다.")
    if settings["audit_integrity"]["signature_required"] and not settings["audit_integrity"]["signing_configured"]:
        warning("AUDIT_SIGNATURE_REQUIRED_WITHOUT_KEY", "HIGH", "감사 체크포인트 서명 필수 모드에 활성 키가 없습니다.")
    elif not settings["audit_integrity"]["signing_configured"]:
        warning("AUDIT_CHECKPOINT_UNSIGNED", "MEDIUM", "감사 체크포인트 활성 HMAC 서명 키가 설정되지 않았습니다.")
    if signing_config.keys and len(signing_config.keys) == 1:
        warning("SIGNING_KEYRING_SINGLE_KEY", "LOW", "키 교체 중 과거 서명 검증을 유지하려면 기존 키와 새 키를 함께 키링에 보관하세요.")
    if settings["recovery"]["scheduled_interval_hours"] <= 0:
        warning("SCHEDULED_BACKUP_DISABLED", "LOW", "예약 복구 번들이 비활성화되어 있습니다.")
    if settings["maintenance"]["interval_minutes"] <= 0:
        warning("MAINTENANCE_DISABLED", "LOW", "예약 유지관리가 비활성화되어 있습니다.")
    if settings["maintenance"]["audit_retention_days"] <= 0:
        warning("AUDIT_RETENTION_UNBOUNDED", "LOW", "감사 이력 보존기간이 무제한입니다.")
    if settings["maintenance"]["import_retention_days"] <= 0:
        warning("IMPORT_RETENTION_UNBOUNDED", "LOW", "가져오기 이력 보존기간이 무제한입니다.")
    if settings["maintenance"]["execution_receipt_retention_days"] <= 0:
        warning("EXECUTION_RECEIPT_RETENTION_UNBOUNDED", "MEDIUM", "상세 실행 영수증 보존기간이 무제한입니다.")
    if settings["export_storage"]["quota_mb"] <= 0:
        warning("EXPORT_QUOTA_UNBOUNDED", "MEDIUM", "내보내기 저장소 quota가 비활성화되어 디스크 사용량이 제한되지 않습니다.")
    if settings["export_storage"]["minimum_free_mb"] < 64:
        warning("EXPORT_DISK_RESERVE_LOW", "MEDIUM", "내보내기 저장소 최소 여유 공간이 64MB 미만입니다.")
    if settings["export_storage"]["retention_days"] <= 0:
        warning("EXPORT_RETENTION_UNBOUNDED", "LOW", "내보내기 산출물 자동 만료가 비활성화되어 있습니다.")
    osv_scheme = settings["supply_chain_intelligence"]["api_scheme"]
    if osv_scheme != "https":
        warning("OSV_API_NOT_HTTPS", "HIGH", "OSV 공급망 위협정보 API가 HTTPS가 아닙니다. 루프백 시험 외에는 허용하지 마세요.")
    if settings["supply_chain_intelligence"]["batch_size"] > 200:
        warning("OSV_BATCH_TOO_LARGE", "MEDIUM", "OSV batch size가 애플리케이션 안전 상한을 초과합니다.")
    evidence_mode = settings["evidence_store"]["scanner_mode"]
    if evidence_mode == "disabled":
        warning("EVIDENCE_SCANNER_DISABLED", "HIGH", "증거 보안 검사가 비활성화되어 관리자 면제 없이는 안전성을 확인할 수 없습니다.")
    elif evidence_mode == "builtin":
        warning("EVIDENCE_SCANNER_BASELINE_ONLY", "MEDIUM", "builtin 검사는 EICAR 기준선 확인이며 실제 악성코드 엔진을 대체하지 않습니다.")
    if not settings["evidence_store"]["clean_required"]:
        warning("EVIDENCE_CLEAN_NOT_REQUIRED", "HIGH", "검사 완료 전 증거 다운로드와 조치 검증 사용이 허용됩니다.")
    if settings["recovery"]["retention_count"] < 2:
        warning("BACKUP_RETENTION_LOW", "MEDIUM", "복구 번들 보존 개수가 2개 미만입니다.")
    if not settings["pagination"]["cursor_signing_key_configured"]:
        warning("CURSOR_SIGNING_KEY_EPHEMERAL", "LOW", "고정 커서 서명 키가 없어 재시작·다중 프로세스 간 페이지 커서가 유지되지 않을 수 있습니다.")

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest = max((severity_order.get(item["severity"], 0) for item in findings), default=0)
    posture = "attention" if highest >= 2 else ("review" if highest == 1 else "healthy")
    return {
        "generated_at": utc_now(),
        "posture": posture,
        "settings": settings,
        "findings": findings,
    }


def _table_counts(db_path: str | Path) -> dict[str, int]:
    wanted = [
        "findings", "import_batches", "audit_events", "risk_approval_requests",
        "maintenance_runs", "database_maintenance_runs", "webhook_events", "idempotency_records", "policy_versions",
        "policy_activation_requests", "background_jobs", "schema_migrations",
        "sbom_documents", "sbom_components", "sbom_finding_links", "vex_statements",
        "osv_scan_runs", "osv_vulnerability_records", "sbom_osv_matches",
        "assets", "asset_identifiers", "asset_identity_candidates",
        "asset_merge_requests", "asset_merge_history",
        "asset_merge_rollback_journals", "asset_merge_rollback_requests",
        "export_artifacts", "config_baselines", "config_drift_checks", "config_change_requests",
        "integrity_proof_key_transitions", "integrity_proof_key_revocations",
        "integrity_proof_revocation_checkpoints", "integrity_proof_checkpoint_witnesses",
    ]
    counts: dict[str, int] = {}
    with connect(db_path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in wanted:
            if table in tables:
                counts[table] = int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    return counts


def _active_policy(db_path: str | Path) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT policy_id,version,name,content_sha256,content_yaml FROM policy_versions WHERE status='ACTIVE' LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _evidence_rows(db_path: str | Path) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='verification_evidence_artifacts'"
        ).fetchone()
        if not table:
            return []
        rows = conn.execute(
            """SELECT evidence_id,verification_id,finding_id,stored_filename,original_filename,
                      content_type,size_bytes,sha256,notes,status,uploaded_by,uploaded_at,
                      retired_by,retired_at,retire_reason,scan_status,scan_engine,scan_signature,
                      scan_details,scanned_at,scan_error,scan_waived_by,scan_waived_at,scan_waiver_reason,
                      source_type,source_reference,acquisition_method,collected_by,collected_at,
                      current_custodian,custody_last_seq,custody_last_hash
                 FROM verification_evidence_artifacts
                WHERE status!='PURGED'
                ORDER BY uploaded_at,evidence_id"""
        ).fetchall()
    return [dict(row) for row in rows]


def _prepare_evidence_files(
    db_path: str | Path, evidence_dir: str | Path | None, temp: Path
) -> tuple[dict[str, Any], list[tuple[Path, str]]]:
    rows = _evidence_rows(db_path)
    evidence_root = Path(evidence_dir) if evidence_dir else None
    output: list[tuple[Path, str]] = []
    entries: list[dict[str, Any]] = []
    bundle_dir = temp / "evidence"
    if rows:
        if evidence_root is None:
            raise ValueError("증거 파일이 있지만 evidence_dir이 지정되지 않았습니다.")
        bundle_dir.mkdir(parents=True, exist_ok=True)
    for row in rows:
        stored = Path(str(row.get("stored_filename") or "")).name
        if not stored or stored != str(row.get("stored_filename") or ""):
            raise ValueError("증거 저장 파일명이 올바르지 않습니다.")
        source = evidence_root / stored  # type: ignore[operator]
        if not source.is_file():
            raise ValueError(f"복구 번들에 포함할 증거 파일이 없습니다: {row['evidence_id']}")
        actual_size = source.stat().st_size
        actual_hash = sha256_file(source)
        if actual_size != int(row.get("size_bytes") or -1) or actual_hash != str(row.get("sha256") or ""):
            raise ValueError(f"증거 파일 무결성 검증에 실패했습니다: {row['evidence_id']}")
        target = bundle_dir / stored
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        arcname = f"evidence/{stored}"
        output.append((target, arcname))
        custody_integrity = verify_evidence_custody_chain(db_path, str(row["evidence_id"]))
        if not custody_integrity.get("valid"):
            raise ValueError(f"증거 보관 사슬 무결성 검증에 실패했습니다: {row['evidence_id']}")
        entries.append({
            "evidence_id": row["evidence_id"],
            "verification_id": row["verification_id"],
            "finding_id": row["finding_id"],
            "path": arcname,
            "original_filename": row["original_filename"],
            "content_type": row["content_type"],
            "size_bytes": actual_size,
            "sha256": actual_hash,
            "status": row["status"],
            "uploaded_by": row["uploaded_by"],
            "uploaded_at": row["uploaded_at"],
            "retired_by": row.get("retired_by"),
            "retired_at": row.get("retired_at"),
            "retire_reason": row.get("retire_reason"),
            "scan_status": row.get("scan_status"),
            "scan_engine": row.get("scan_engine"),
            "scan_signature": row.get("scan_signature"),
            "scanned_at": row.get("scanned_at"),
            "scan_error": row.get("scan_error"),
            "scan_waived_by": row.get("scan_waived_by"),
            "scan_waived_at": row.get("scan_waived_at"),
            "scan_waiver_reason": row.get("scan_waiver_reason"),
            "source_type": row.get("source_type"),
            "source_reference": row.get("source_reference"),
            "acquisition_method": row.get("acquisition_method"),
            "collected_by": row.get("collected_by"),
            "collected_at": row.get("collected_at"),
            "current_custodian": row.get("current_custodian"),
            "custody_last_seq": row.get("custody_last_seq"),
            "custody_last_hash": row.get("custody_last_hash"),
            "custody_integrity": custody_integrity,
        })
    manifest = {
        "format": EVIDENCE_MANIFEST_FORMAT,
        "artifact_count": len(entries),
        "total_size_bytes": sum(int(item["size_bytes"]) for item in entries),
        "artifacts": entries,
    }
    manifest_path = temp / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    output.append((manifest_path, "evidence-manifest.json"))
    return manifest, output


def _validate_evidence_bundle(temp: Path, database: Path, names: set[str]) -> dict[str, Any]:
    schema_version = int(get_schema_info(database).get("schema_version") or 0)
    manifest_path = temp / "evidence-manifest.json"
    if not manifest_path.exists():
        if schema_version >= 15:
            raise ValueError("15 이상 복구 번들에는 evidence-manifest.json이 필요합니다.")
        return {"format": EVIDENCE_MANIFEST_FORMAT, "artifact_count": 0, "total_size_bytes": 0, "artifacts": []}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("evidence-manifest.json 형식이 올바르지 않습니다.") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != EVIDENCE_MANIFEST_FORMAT:
        raise ValueError("지원하지 않는 증거 manifest 형식입니다.")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("증거 manifest artifacts가 올바르지 않습니다.")
    expected_paths: set[str] = set()
    ids: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("증거 manifest 항목이 올바르지 않습니다.")
        evidence_id = str(item.get("evidence_id") or "")
        path = str(item.get("path") or "")
        if not evidence_id or evidence_id in ids:
            raise ValueError("증거 manifest의 evidence_id가 비어 있거나 중복되었습니다.")
        ids.add(evidence_id)
        pure = PurePosixPath(path)
        if len(pure.parts) != 2 or pure.parts[0] != "evidence" or Path(pure.parts[1]).name != pure.parts[1]:
            raise ValueError("증거 manifest 경로가 올바르지 않습니다.")
        if path in expected_paths:
            raise ValueError("증거 manifest 파일 경로가 중복되었습니다.")
        expected_paths.add(path)
        target = temp / path
        if not target.is_file():
            raise ValueError(f"증거 파일이 복구 번들에 없습니다: {evidence_id}")
        if target.stat().st_size != int(item.get("size_bytes") or -1):
            raise ValueError(f"증거 파일 크기가 일치하지 않습니다: {evidence_id}")
        if sha256_file(target) != str(item.get("sha256") or ""):
            raise ValueError(f"증거 파일 해시가 일치하지 않습니다: {evidence_id}")
    actual_paths = {name for name in names if name.startswith("evidence/")}
    if actual_paths != expected_paths:
        raise ValueError("복구 번들의 증거 파일 목록이 manifest와 일치하지 않습니다.")
    with connect(database) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='verification_evidence_artifacts'"
        ).fetchone()
        rows = conn.execute(
            "SELECT evidence_id,verification_id,finding_id,stored_filename,size_bytes,sha256,status,scan_status,scan_engine,scan_signature,scanned_at,scan_error,scan_waived_by,scan_waived_at,scan_waiver_reason,source_type,source_reference,acquisition_method,collected_by,collected_at,current_custodian,custody_last_seq,custody_last_hash FROM verification_evidence_artifacts WHERE status!='PURGED'"
        ).fetchall() if table else []
    db_records = {str(row["evidence_id"]): dict(row) for row in rows}
    if set(db_records) != ids:
        raise ValueError("데이터베이스 증거 레코드와 evidence manifest가 일치하지 않습니다.")
    for item in artifacts:
        row = db_records[str(item["evidence_id"])]
        expected_path = f"evidence/{row['stored_filename']}"
        for field in ("verification_id", "finding_id", "size_bytes", "sha256", "status", "scan_status", "scan_engine", "scan_signature", "scanned_at", "scan_error", "scan_waived_by", "scan_waived_at", "scan_waiver_reason", "source_type", "source_reference", "acquisition_method", "collected_by", "collected_at", "current_custodian", "custody_last_seq", "custody_last_hash"):
            if str(row[field]) != str(item.get(field)):
                raise ValueError(f"증거 manifest의 {field}가 데이터베이스와 일치하지 않습니다.")
        if item.get("path") != expected_path:
            raise ValueError("증거 manifest 저장 경로가 데이터베이스와 일치하지 않습니다.")
        custody = verify_evidence_custody_chain(database, str(item["evidence_id"]))
        if not custody.get("valid"):
            raise ValueError(f"증거 보관 사슬 무결성 검증에 실패했습니다: {item['evidence_id']}")
        manifest_custody = item.get("custody_integrity") or {}
        for field in ("event_count", "last_seq", "last_hash", "current_custodian"):
            if str(custody.get(field)) != str(manifest_custody.get(field)):
                raise ValueError(f"증거 manifest의 보관 사슬 {field}가 일치하지 않습니다.")
    if int(manifest.get("artifact_count", -1)) != len(artifacts):
        raise ValueError("증거 manifest artifact_count가 일치하지 않습니다.")
    return manifest


def create_recovery_bundle(
    db_path: str | Path,
    destination: str | Path,
    *,
    config_audit: dict[str, Any] | None = None,
    signing_key: str = "",
    signing_key_id: str | None = None,
    signing_keys: Mapping[str, str] | None = None,
    audit_signing_key: str = "",
    audit_signing_keys: Mapping[str, str] | None = None,
    created_by: str = "system",
    base_dir: str | Path | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    if signing_key_id and not signing_key:
        raise ValueError("복구 번들 key_id에는 서명 키가 필요합니다.")
    if signing_key_id and not KEY_ID_RE.fullmatch(signing_key_id):
        raise ValueError("복구 번들 서명 키 ID 형식이 올바르지 않습니다.")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vulnflow_recovery_") as temp_name:
        temp = Path(temp_name)
        database = temp / "database.sqlite3"
        backup_database(db_path, database)
        database_summary = validate_database_file(database)
        policy = _active_policy(database)
        audit = config_audit or build_config_audit(db_path=db_path, base_dir=base_dir)
        (temp / "config-audit.json").write_text(
            json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        audit_integrity = verify_audit_integrity(
            database, signing_key=audit_signing_key, signing_keys=dict(audit_signing_keys or {})
        )
        if not audit_integrity.get("valid"):
            raise ValueError("감사 체인 무결성이 유효하지 않아 복구 번들을 생성할 수 없습니다.")
        (temp / "audit-integrity.json").write_text(
            json.dumps(audit_integrity, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        if policy:
            (temp / "active-policy.yml").write_text(str(policy.pop("content_yaml")), encoding="utf-8")
        evidence_manifest, evidence_files = _prepare_evidence_files(db_path, evidence_dir, temp)
        manifest: dict[str, Any] = {
            "format": RECOVERY_FORMAT,
            "created_at": utc_now(),
            "created_by": created_by,
            "app_version": _app_version(base_dir),
            "schema": get_schema_info(database),
            "database": database_summary | {
                "filename": database.name,
                "sha256": sha256_file(database),
            },
            "table_counts": _table_counts(database),
            "active_policy": policy,
            "evidence": {
                "artifact_count": evidence_manifest["artifact_count"],
                "total_size_bytes": evidence_manifest["total_size_bytes"],
            },
            "signed": bool(signing_key),
            "signature": ({
                "algorithm": "HMAC-SHA256",
                "key_id": signing_key_id,
            } if signing_key else None),
        }
        manifest_bytes = _canonical_json(manifest)
        manifest_path = temp / "manifest.json"
        manifest_path.write_bytes(manifest_bytes)

        # SQLite read-only validation can create short-lived -shm/-wal sidecars.
        # Recovery bundles must contain only the explicitly defined portable files,
        # never transient SQLite runtime artifacts discovered by directory scanning.
        files_to_hash: list[tuple[Path, str]] = [
            (database, "database.sqlite3"),
            (temp / "config-audit.json", "config-audit.json"),
            (temp / "audit-integrity.json", "audit-integrity.json"),
            (manifest_path, "manifest.json"),
        ]
        active_policy_path = temp / "active-policy.yml"
        if active_policy_path.exists():
            files_to_hash.append((active_policy_path, "active-policy.yml"))
        files_to_hash.extend(evidence_files)
        files_to_hash = sorted(files_to_hash, key=lambda item: item[1])
        sums_bytes = ("\n".join(f"{sha256_file(path)}  {arcname}" for path, arcname in files_to_hash) + "\n").encode("utf-8")
        sums_path = temp / "SHA256SUMS.txt"
        sums_path.write_bytes(sums_bytes)
        bundle_files: list[tuple[Path, str]] = files_to_hash + [(sums_path, "SHA256SUMS.txt")]
        if signing_key:
            signature_payload = manifest_bytes + b"\n" + sums_bytes
            signature = hmac_sha256(signing_key, signature_payload)
            signature_path = temp / "manifest.hmac"
            signature_path.write_text(signature + "\n", encoding="ascii")
            bundle_files.append((signature_path, "manifest.hmac"))
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path, arcname in sorted(bundle_files, key=lambda item: item[1]):
                archive.write(path, arcname=arcname)
    return manifest | {"bundle_path": str(destination), "bundle_sha256": sha256_file(destination)}


def _safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > MAX_BUNDLE_FILES:
        raise ValueError("복구 번들 파일 수가 허용 범위를 초과합니다.")
    total = 0
    seen: set[str] = set()
    for info in infos:
        if info.filename in seen:
            raise ValueError("복구 번들에 중복 파일명이 포함되어 있습니다.")
        seen.add(info.filename)
        name = PurePosixPath(info.filename)
        allowed_nested = len(name.parts) == 2 and name.parts[0] == "evidence" and Path(name.parts[1]).name == name.parts[1]
        if name.is_absolute() or ".." in name.parts or not (len(name.parts) == 1 or allowed_nested):
            raise ValueError("복구 번들에 안전하지 않은 경로가 포함되어 있습니다.")
        if info.is_dir():
            continue
        mode = (int(info.external_attr) >> 16) & 0o170000
        if mode and stat.S_ISLNK(mode):
            raise ValueError("복구 번들에 심볼릭 링크가 포함될 수 없습니다.")
        total += int(info.file_size)
        if total > MAX_BUNDLE_UNCOMPRESSED:
            raise ValueError("복구 번들의 압축 해제 크기가 허용 범위를 초과합니다.")
    return infos


def _read_sums(path: Path) -> dict[str, str]:
    output: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, sep, filename = line.partition("  ")
        if not sep or not re_full_sha256(digest) or not filename:
            raise ValueError("SHA256SUMS.txt 형식이 올바르지 않습니다.")
        output[filename] = digest.lower()
    return output


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)


def validate_recovery_bundle(
    bundle_path: str | Path,
    *,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    audit_signing_key: str = "",
    audit_signing_keys: Mapping[str, str] | None = None,
    require_signature: bool = False,
    current_schema_version: int | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    if not bundle.is_file() or bundle.stat().st_size == 0:
        raise ValueError("복구 번들이 비어 있거나 존재하지 않습니다.")
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow_recovery_validate_") as temp_name:
            temp = Path(temp_name)
            with zipfile.ZipFile(bundle) as archive:
                infos = _safe_members(archive)
                names = {info.filename for info in infos if not info.is_dir()}
                missing = REQUIRED_FILES - names
                if missing:
                    raise ValueError("복구 번들 필수 파일이 없습니다: " + ", ".join(sorted(missing)))
                archive.extractall(temp)
            sums_path = temp / "SHA256SUMS.txt"
            sums_bytes = sums_path.read_bytes()
            sums = _read_sums(sums_path)
            expected_hashed_files = names - {"SHA256SUMS.txt", "manifest.hmac"}
            if set(sums) != expected_hashed_files:
                missing_hashes = expected_hashed_files - set(sums)
                extra_hashes = set(sums) - expected_hashed_files
                detail = []
                if missing_hashes:
                    detail.append("해시 누락: " + ", ".join(sorted(missing_hashes)))
                if extra_hashes:
                    detail.append("알 수 없는 해시: " + ", ".join(sorted(extra_hashes)))
                raise ValueError("SHA256SUMS.txt 대상 목록 불일치 (" + "; ".join(detail) + ")")
            for filename, expected in sums.items():
                target = temp / filename
                if not target.is_file():
                    raise ValueError(f"해시 대상 파일이 없습니다: {filename}")
                if sha256_file(target) != expected:
                    raise ValueError(f"복구 번들 파일 해시 불일치: {filename}")
            manifest_bytes = (temp / "manifest.json").read_bytes()
            try:
                manifest = json.loads(manifest_bytes)
            except json.JSONDecodeError as exc:
                raise ValueError("manifest.json 형식이 올바르지 않습니다.") from exc
            if not isinstance(manifest, dict):
                raise ValueError("manifest.json은 JSON 객체여야 합니다.")
            if manifest.get("format") != RECOVERY_FORMAT:
                raise ValueError("지원하지 않는 복구 번들 형식입니다.")
            signed = bool(manifest.get("signed"))
            signature_file = temp / "manifest.hmac"
            if not signed and signature_file.exists():
                raise ValueError("서명 상태와 manifest.hmac 파일이 일치하지 않습니다.")
            if require_signature and not signed:
                raise ValueError("서명되지 않은 복구 번들은 허용되지 않습니다.")
            resolved_signing_key_id: str | None = None
            if signed:
                if not signature_file.is_file():
                    raise ValueError("서명 파일이 없습니다.")
                supplied = signature_file.read_text(encoding="ascii").strip()
                signature_payload = manifest_bytes + b"\n" + sums_bytes
                signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
                declared_key_id = str(signature_meta.get("key_id") or "") or None
                verified = verify_hmac(
                    signature=supplied, payload=signature_payload,
                    signing_keys=signing_keys, key_id=declared_key_id, legacy_key=signing_key,
                )
                if not verified["valid"]:
                    raise ValueError(
                        "복구 번들 HMAC 서명이 일치하지 않거나 필요한 키를 사용할 수 없습니다: "
                        + str(verified["status"])
                    )
                resolved_signing_key_id = verified.get("resolved_key_id")
            database = temp / "database.sqlite3"
            db_summary = validate_database_file(database)
            evidence_report = _validate_evidence_bundle(temp, database, names)
            audit_report = verify_audit_integrity(
                database, signing_key=audit_signing_key, signing_keys=dict(audit_signing_keys or {})
            )
            if not audit_report.get("valid"):
                raise ValueError("복구 번들의 감사 체인 무결성 검증에 실패했습니다.")
            try:
                recorded_audit = json.loads((temp / "audit-integrity.json").read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise ValueError("audit-integrity.json 형식이 올바르지 않습니다.") from exc
            for field in ("anchor_seq", "anchor_hash", "last_seq", "last_hash", "checked_events"):
                if recorded_audit.get(field) != audit_report.get(field):
                    raise ValueError(f"audit-integrity.json의 {field} 값이 데이터베이스와 일치하지 않습니다.")
            manifest_db = dict(manifest.get("database") or {})
            if manifest_db.get("sha256") != sha256_file(database):
                raise ValueError("manifest의 데이터베이스 해시가 일치하지 않습니다.")
            bundle_schema = int((manifest.get("schema") or {}).get("schema_version") or db_summary.get("schema_version") or 0)
            if current_schema_version is not None and bundle_schema > int(current_schema_version):
                raise ValueError("현재 애플리케이션보다 새로운 스키마의 복구 번들입니다.")
            return {
                "valid": True,
                "bundle_sha256": sha256_file(bundle),
                "manifest": manifest,
                "database": db_summary,
                "signed": signed,
                "signing_key_id": resolved_signing_key_id,
                "files": sorted(sums),
                "audit_integrity": audit_report,
                "evidence": {
                    "artifact_count": evidence_report.get("artifact_count", 0),
                    "total_size_bytes": evidence_report.get("total_size_bytes", 0),
                },
            }
    except zipfile.BadZipFile as exc:
        raise ValueError("유효한 ZIP 복구 번들이 아닙니다.") from exc


def restore_recovery_bundle(
    db_path: str | Path,
    bundle_path: str | Path,
    *,
    actor: str,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    audit_signing_key: str = "",
    audit_signing_keys: Mapping[str, str] | None = None,
    require_signature: bool = False,
    current_schema_version: int | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    validation = validate_recovery_bundle(
        bundle_path,
        signing_key=signing_key, signing_keys=signing_keys,
        audit_signing_key=audit_signing_key, audit_signing_keys=audit_signing_keys,
        require_signature=require_signature,
        current_schema_version=current_schema_version, evidence_dir=evidence_dir,
    )
    if int((validation.get("evidence") or {}).get("artifact_count") or 0) > 0 and evidence_dir is None:
        raise ValueError("증거 파일이 포함된 복구 번들에는 evidence_dir이 필요합니다.")
    with tempfile.TemporaryDirectory(prefix="vulnflow_recovery_restore_") as temp_name:
        temp = Path(temp_name)
        with zipfile.ZipFile(bundle_path) as archive:
            infos = _safe_members(archive)
            for info in infos:
                if info.filename == "database.sqlite3" or info.filename == "evidence-manifest.json" or info.filename.startswith("evidence/"):
                    archive.extract(info, temp)
        evidence_root = Path(evidence_dir) if evidence_dir else None
        previous_dir: Path | None = None
        staged_dir = temp / "evidence"
        replaced_evidence = False
        if evidence_root is not None:
            evidence_root.parent.mkdir(parents=True, exist_ok=True)
            previous_dir = evidence_root.parent / f".{evidence_root.name}.pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
            if evidence_root.exists():
                os.replace(evidence_root, previous_dir)
            if staged_dir.exists():
                os.replace(staged_dir, evidence_root)
            else:
                evidence_root.mkdir(parents=True, exist_ok=True)
            replaced_evidence = True
        try:
            restored = restore_database(db_path, temp / "database.sqlite3", actor=actor)
        except Exception:
            if replaced_evidence and evidence_root is not None:
                shutil.rmtree(evidence_root, ignore_errors=True)
                if previous_dir and previous_dir.exists():
                    os.replace(previous_dir, evidence_root)
            raise
        if previous_dir and previous_dir.exists():
            shutil.rmtree(previous_dir, ignore_errors=True)
    return {"validation": validation, "restore": restored}


def list_recovery_bundles(directory: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    root = Path(directory)
    if not root.exists():
        return []
    output: list[dict[str, Any]] = []
    for path in sorted(root.glob("vulnflow_recovery_*.zip"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
        signed = None
        signing_key_id = None
        try:
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("manifest.json"))
            signed = bool(manifest.get("signed"))
            signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
            signing_key_id = str(signature_meta.get("key_id") or "") or ("legacy-unidentified" if signed else None)
        except Exception:
            pass
        output.append({
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "modified_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).replace(microsecond=0).isoformat(),
            "sha256": sha256_file(path),
            "signed": signed,
            "signing_key_id": signing_key_id,
        })
    return output


def prune_recovery_bundles(directory: str | Path, *, keep_count: int) -> int:
    root = Path(directory)
    if not root.exists():
        return 0
    files = sorted(root.glob("vulnflow_recovery_*.zip"), key=lambda item: item.stat().st_mtime, reverse=True)
    removed = 0
    for path in files[max(0, int(keep_count)):]:
        path.unlink(missing_ok=True)
        removed += 1
    return removed


def create_scheduled_recovery_bundle(
    db_path: str | Path,
    directory: str | Path,
    *,
    signing_key: str,
    signing_key_id: str | None = None,
    signing_keys: Mapping[str, str] | None = None,
    audit_signing_key: str = "",
    audit_signing_keys: Mapping[str, str] | None = None,
    retention_count: int,
    actor: str,
    base_dir: str | Path | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = root / f"vulnflow_recovery_{timestamp}.zip"
    result = create_recovery_bundle(
        db_path,
        destination,
        signing_key=signing_key, signing_key_id=signing_key_id, signing_keys=signing_keys,
        audit_signing_key=audit_signing_key, audit_signing_keys=audit_signing_keys,
        created_by=actor,
        base_dir=base_dir,
        evidence_dir=evidence_dir,
    )
    result["pruned"] = prune_recovery_bundles(root, keep_count=max(1, int(retention_count)))
    return result
