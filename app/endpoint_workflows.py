from __future__ import annotations

"""Request-facing workflow composition without importing :mod:`app.main`.

The ASGI entrypoint historically owned request authentication helpers, policy
selection, scoring orchestration, maintenance settings, intelligence refresh,
and small read-model adapters.  This module keeps those workflows in one
explicit, app-instance-aware object while the legacy names remain available
from ``app.main`` as thin compatibility wrappers.
"""

import csv
import hmac
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, MutableMapping

from fastapi import HTTPException, Request

from app.core.project_scope import active_project
from app.services.service_invocation import call_with_supported_options


STATUS_TRANSITIONS = {
    "OPEN": frozenset({"OPEN", "IN_PROGRESS", "MITIGATED", "RISK_ACCEPTED", "CLOSED"}),
    "IN_PROGRESS": frozenset({"OPEN", "IN_PROGRESS", "MITIGATED", "RISK_ACCEPTED", "CLOSED"}),
    "MITIGATED": frozenset({"MITIGATED", "OPEN", "IN_PROGRESS", "CLOSED"}),
    "RISK_ACCEPTED": frozenset({"RISK_ACCEPTED", "OPEN", "IN_PROGRESS", "CLOSED"}),
    "CLOSED": frozenset({"CLOSED", "OPEN"}),
}



NOTICE_MESSAGES = {
    "upload_ok": "취약점 결과를 반영했습니다.",
    "upload_partial": "유효한 취약점만 반영했습니다. 제외된 행은 가져오기 오류 CSV에서 확인하세요.",
    "intel_ok": "CISA KEV·FIRST EPSS 정보를 갱신했습니다.",
    "intel_partial": "일부 위협정보만 갱신했습니다. 세부 오류는 감사 이력과 서버 메시지를 확인하세요.",
    "workflow_ok": "조치 워크플로를 저장하고 재평가했습니다.",
    "rescore_ok": "현재 정책으로 전체 항목을 재평가했습니다.",
    "reset_ok": "데모 데이터를 초기화했습니다.",
    "bulk_ok": "선택한 취약점의 워크플로를 일괄 변경했습니다.",
    "restore_ok": "SQLite 백업을 복원하고 현재 정책으로 재평가했습니다.",
    "record_state_ok": "레코드 상태를 변경했습니다.",
    "approval_requested": "위험수용 승인 요청을 생성했습니다.",
    "approval_decided": "위험수용 승인 요청을 처리했습니다.",
    "verification_requested": "조치 검증 요청을 생성했습니다.",
    "verification_decided": "조치 검증 요청을 처리했습니다.",
    "evidence_uploaded": "조치 검증 증거를 안전하게 저장했습니다.",
    "evidence_retired": "조치 검증 증거를 보관해제 처리했습니다. 파일은 무결성 추적을 위해 유지됩니다.",
    "evidence_scanned": "조치 검증 증거의 보안 검사를 완료했습니다.",
    "evidence_scan_waived": "관리자 승인으로 증거 검사 요구를 면제했습니다.",
    "evidence_transferred": "증거 보관 책임자 인계를 기록했습니다.",
    "maintenance_ok": "유지관리 작업을 완료했습니다.",
    "webhook_ok": "대기 중인 웹훅 전송을 실행했습니다.",
    "webhook_retry": "웹훅 이벤트를 재시도 대기 상태로 전환했습니다.",
    "policy_uploaded": "정책 초안을 등록했습니다.",
    "policy_requested": "정책 활성화 승인 요청을 생성했습니다.",
    "asset_merge_requested": "자산 병합 승인 요청을 생성했습니다.",
    "asset_merge_decided": "자산 병합 승인 요청을 처리했습니다.",
    "asset_merge_rollback_requested": "자산 병합 롤백 승인 요청을 생성했습니다.",
    "asset_merge_rollback_decided": "자산 병합 롤백 승인 요청을 처리했습니다.",
    "policy_decided": "정책 활성화 요청을 처리했습니다.",
    "job_queued": "백그라운드 작업을 등록했습니다.",
    "job_cancelled": "백그라운드 작업 취소를 요청했습니다.",
    "job_retried": "백그라운드 작업을 재시도 대기 상태로 전환했습니다.",
    "export_queued": "취약점 CSV 스냅샷 내보내기 작업을 등록했습니다.",
    "export_expired": "내보내기 산출물을 만료 처리했습니다.",
    "export_pinned": "내보내기 산출물을 저장공간 정리에서 보호했습니다.",
    "export_unpinned": "내보내기 산출물 보호를 해제했습니다.",
    "export_storage_cleaned": "내보내기 저장공간 정리를 완료했습니다.",
    "recovery_ok": "복구 번들을 생성했습니다.",
    "recovery_restored": "복구 번들을 검증하고 복원했습니다.",
    "audit_checkpoint": "서명된 감사 체크포인트를 생성했습니다.",
    "integrity_proof_created": "외부 검증용 무결성 증명 번들을 생성했습니다.",
    "integrity_proof_key_transition_created": "교차서명된 Ed25519 proof 키 전환을 등록했습니다.",
    "integrity_proof_key_revocation_created": "비상 Ed25519 proof 키 폐기와 대체 키 복구 문서를 등록했습니다.",
    "integrity_proof_revocation_checkpoint_created": "Revocation registry 신뢰 checkpoint를 생성했습니다.",
    "source_resolution_ok": "다중 스캐너 충돌 조정 결정을 저장했습니다.",
    "config_baseline_created": "현재 구성을 새 기준선으로 승인했습니다.",
    "config_drift_checked": "구성 드리프트 검사 결과를 감사 이력에 기록했습니다.",
    "config_change_requested": "구성 변경 승인 요청을 생성했습니다.",
    "config_change_decided": "구성 변경 승인 요청을 처리했습니다.",
    "config_change_applied": "승인된 구성 변경을 새 기준선으로 승격했습니다.",
    "jira_queued": "Jira 티켓 생성 작업을 예약했습니다.",
}


class EndpointWorkflows:
    """App-instance-aware request workflow composition.

    ``namespace`` is the historical application namespace.  Looking values up
    at call time intentionally preserves operator/test monkeypatch behaviour
    while removing the implementation bodies from the ASGI entrypoint.
    """

    def __init__(self, namespace: MutableMapping[str, Any]):
        self.namespace = namespace

    def runtime_context(self, context: Any | None = None):
        if context is not None:
            return context
        current = self.namespace.get("APPLICATION_CONTEXT")
        if current is None:
            raise RuntimeError("application context is not initialized")
        return current

    def runtime_value(self, context: Any | None, name: str, fallback: Any = None) -> Any:
        if context is None and "APPLICATION_CONTEXT" not in self.namespace:
            return self.namespace.get(name, fallback)
        return self.runtime_context(context).get(name, fallback)

    def runtime_service(self, context: Any | None, name: str):
        runtime = self.runtime_context(context)
        value = runtime.get(name, None)
        if value is None:
            raise KeyError(f"application runtime service is missing: {name}")
        return value

    def signing_config(self, context: Any | None = None):
        ns = self.namespace
        return ns["build_signing_config"](
            signing_keys_json=self.runtime_value(context, "SIGNING_KEYS_JSON", ns["SIGNING_KEYS_JSON"]),
            audit_active_key_id=self.runtime_value(context, "AUDIT_ACTIVE_KEY_ID", ns["AUDIT_ACTIVE_KEY_ID"]),
            backup_active_key_id=self.runtime_value(context, "BACKUP_ACTIVE_KEY_ID", ns["BACKUP_ACTIVE_KEY_ID"]),
            legacy_audit_key=self.runtime_value(context, "AUDIT_SIGNING_KEY", ns["AUDIT_SIGNING_KEY"]),
            legacy_backup_key=self.runtime_value(context, "BACKUP_SIGNING_KEY", ns["BACKUP_SIGNING_KEY"]),
            require_audit=bool(self.runtime_value(context, "AUDIT_REQUIRE_SIGNATURE", ns["AUDIT_REQUIRE_SIGNATURE"])),
            require_backup=bool(self.runtime_value(context, "BACKUP_REQUIRE_SIGNATURE", ns["BACKUP_REQUIRE_SIGNATURE"])),
        )

    def audit_signing(self, context: Any | None = None):
        config = self.signing_config(context)
        key_id, secret = config.active("audit")
        return config, key_id, secret

    def ed25519_config(self, role: str, context: Any | None = None):
        ns = self.namespace
        prefix = {
            "proof": "INTEGRITY_PROOF",
            "witness": "INTEGRITY_WITNESS",
            "transparency": "INTEGRITY_TRANSPARENCY",
            "mirror": "INTEGRITY_MIRROR",
        }[role]
        require_private = role == "proof" and bool(
            self.runtime_value(
                context,
                "INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE",
                ns["INTEGRITY_PROOF_REQUIRE_PUBLIC_SIGNATURE"],
            )
        )
        return ns["build_ed25519_signing_config"](
            private_keys_json=self.runtime_value(context, f"{prefix}_PRIVATE_KEYS_JSON", ns[f"{prefix}_PRIVATE_KEYS_JSON"]),
            public_keys_json=self.runtime_value(context, f"{prefix}_PUBLIC_KEYS_JSON", ns[f"{prefix}_PUBLIC_KEYS_JSON"]),
            active_key_id=self.runtime_value(context, f"{prefix}_ACTIVE_KEY_ID", ns[f"{prefix}_ACTIVE_KEY_ID"]),
            require_private=require_private,
        )

    def backup_signing(self, context: Any | None = None):
        config = self.signing_config(context)
        key_id, secret = config.active("backup")
        return config, key_id, secret

    def create_asset_merge_recovery_bundle(self, request_id: str, actor: str) -> dict[str, Any]:
        ns = self.namespace
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(request_id or "asset-merge"))[:80]
        stamp = ns["utc_now"]().replace("-", "").replace(":", "").replace("+00:00", "Z")
        destination = ns["RECOVERY_DIR"] / "asset-merges" / f"{safe_id}_{stamp}.zip"
        destination.parent.mkdir(parents=True, exist_ok=True)
        signing, backup_key_id, backup_key = self.backup_signing()
        selection = active_project()
        project_id = selection.project_id if selection is not None else "default"
        project_name = selection.name if selection is not None else "기본 프로젝트"
        return ns["create_recovery_bundle"](
            ns["DB_PATH"], destination,
            config_audit=ns["build_config_audit"](
                db_path=ns["DB_PATH"], base_dir=ns["BASE_DIR"], evidence_dir=ns["EVIDENCE_DIR"]
            ),
            signing_key=backup_key, signing_key_id=backup_key_id, signing_keys=signing.keys,
            audit_signing_keys=signing.keys, created_by=actor, base_dir=ns["BASE_DIR"], evidence_dir=ns["EVIDENCE_DIR"],
            project_id=project_id, project_name=project_name,
        )

    def load_sample_rows(self, path: Path, normalize_callback: Any) -> list[dict[str, Any]]:
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise ValueError("샘플 CSV 헤더가 없습니다.")
            return [normalize_callback(dict(row), idx) for idx, row in enumerate(reader)]

    def ensure_policy_registry(self, context: Any | None = None) -> dict[str, Any]:
        ns = self.namespace
        runtime = self.runtime_context(context)
        db_path = runtime.get("DB_PATH")
        policy_path = Path(runtime.get("POLICY_PATH"))
        active = self.runtime_service(runtime, "get_active_policy_version")(db_path)
        if active:
            return active
        policy = ns["load_policy"](policy_path)
        content = policy_path.read_text(encoding="utf-8")
        try:
            return self.runtime_service(runtime, "create_policy_version")(
                db_path, version=str(policy["version"]), name=str(policy["name"]),
                content_yaml=content, content_sha256=ns["policy_digest"](policy),
                created_by="system-migration", status="ACTIVE",
                notes="파일 기반 정책을 정책 레지스트리로 초기 등록",
            )
        except ValueError:
            active = self.runtime_service(runtime, "get_active_policy_version")(db_path)
            if active:
                return active
            raise

    def active_policy_record(self) -> dict[str, Any] | None:
        ns = self.namespace
        db_value = ns["DB_PATH"]
        # Standalone normalization/export helpers may run outside an HTTP or
        # worker project scope.  Optional policy lookup must not silently fall
        # back to the default customer database in that case.
        from app.core.project_scope import ProjectScopedPath, active_project

        if (
            isinstance(db_value, ProjectScopedPath)
            and db_value.require_scope
            and active_project() is None
        ):
            return None
        if not Path(db_value).is_file():
            return None
        try:
            return ns["get_active_policy_version"](db_value)
        except Exception:
            return None

    def policy(self) -> dict[str, Any]:
        ns = self.namespace
        record = self.active_policy_record()
        if record:
            return ns["parse_policy_text"](str(record["content_yaml"]))
        return ns["load_policy"](ns["POLICY_PATH"])

    @staticmethod
    def actor(request: Request) -> str:
        return getattr(request.state, "actor", "local-user")

    @staticmethod
    def new_csrf() -> str:
        return secrets.token_urlsafe(32)

    def verify_csrf(self, request: Request, form_token: str) -> None:
        ns = self.namespace
        context = ns["get_application_context"](request.app)
        cookie_token = request.cookies.get(str(context.get("CSRF_COOKIE", ns["CSRF_COOKIE"])), "")
        if not cookie_token or not form_token or not hmac.compare_digest(cookie_token, form_token):
            raise HTTPException(403, "요청 검증 토큰이 올바르지 않습니다. 페이지를 새로고침한 뒤 다시 시도하세요.")

    def principal(self, request: Request):
        ns = self.namespace
        context = ns["get_application_context"](request.app)
        api_tokens_json = context.get("AUTH_API_TOKENS_JSON", ns["AUTH_API_TOKENS_JSON"])
        session_cookie = str(context.get("AUTH_SESSION_COOKIE", ns["AUTH_SESSION_COOKIE"]))
        session_token = request.cookies.get(session_cookie, "")
        demo_mode = bool(context.get("DEMO_MODE", ns.get("DEMO_MODE", False)))
        proxy_headers_present = any(
            request.headers.get(name)
            for name in ("forwarded", "x-forwarded-for", "x-real-ip", "x-client-ip")
        )
        allow_local_fallback = (
            demo_mode
            and bool(context.get("ALLOW_LOCAL_ADMIN_FALLBACK", ns["ALLOW_LOCAL_ADMIN_FALLBACK"]))
            and not proxy_headers_present
        )
        client_host = request.client.host if request.client is not None else ""
        return ns["authenticate_request"](
            request.headers.get("authorization", ""),
            api_tokens_json=api_tokens_json,
            session_token=session_token,
            db_path=context.get("CONTROL_DB_PATH", context.get("DB_PATH", ns["DB_PATH"])),
            authenticate_session_fn=ns["authenticate_session"],
            allow_local_fallback=allow_local_fallback,
            client_host=client_host,
        user_agent=request.headers.get("user-agent", ""),
        session_binding=str(context.get("AUTH_SESSION_BINDING", "off") or "off"),
        session_idle_minutes=int(context.get("AUTH_SESSION_IDLE_MINUTES", 0) or 0),
        )

    @staticmethod
    def require_api_token(request: Request) -> None:
        if getattr(request.state, "auth_method", "") != "bearer":
            raise HTTPException(403, "쓰기 API는 Bearer API token 인증이 필요합니다.")

    def queue_webhook(
        self, event_type: str, payload: dict[str, Any], actor: str,
        context: Any | None = None, idempotency_key: str | None = None,
    ) -> list[str]:
        runtime = self.runtime_context(context)
        queued = self.runtime_service(runtime, "queue_event_for_integrations")(
            runtime.get("DB_PATH"),
            event_type=event_type,
            payload=payload,
            actor=actor,
            app_base_url=str(runtime.get("PUBLIC_BASE_URL", "") or ""),
            idempotency_key=str(idempotency_key or ""),
        )
        endpoints = dict(runtime.get("WEBHOOK_ENDPOINTS", {}) or {})
        if endpoints:
            queued.extend(self.runtime_service(runtime, "queue_event")(
                runtime.get("DB_PATH"), endpoints=endpoints, event_type=event_type,
                payload=payload, actor=actor, idempotency_key=idempotency_key,
                idempotency_retention_days=int(runtime.get("IDEMPOTENCY_RETENTION_DAYS", 30)),
            ))
        return queued

    def require_role(self, request: Request, minimum: str) -> None:
        if not self.namespace["has_role"](getattr(request.state, "role", "viewer"), minimum):
            raise HTTPException(403, f"이 작업에는 {minimum} 이상의 역할이 필요합니다.")

    def maintenance_settings(self, context: Any | None = None) -> dict[str, Any]:
        runtime = self.runtime_context(context)
        _signing, audit_key_id, audit_key = self.audit_signing(runtime)
        return {
            "audit_retention_days": int(runtime.get("AUDIT_RETENTION_DAYS")),
            "import_retention_days": int(runtime.get("IMPORT_RETENTION_DAYS")),
            "auto_archive_stale_days": int(runtime.get("AUTO_ARCHIVE_STALE_DAYS")),
            "webhook_retention_days": int(runtime.get("WEBHOOK_RETENTION_DAYS")),
            "execution_receipt_retention_days": int(runtime.get("EXECUTION_RECEIPT_RETENTION_DAYS")),
            "audit_signing_key": audit_key,
            "audit_signing_key_id": audit_key_id,
        }

    def purge_completed_jobs(self, context: Any | None = None) -> int:
        runtime = self.runtime_context(context)
        retention_days = int(runtime.get("JOB_RETENTION_DAYS"))
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).replace(microsecond=0).isoformat()
        return self.runtime_service(runtime, "purge_background_jobs")(
            runtime.get("DB_PATH"), completed_before=cutoff
        )

    def prepare_policy_activation(self, request_id: str) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        ns = self.namespace
        approval = ns["get_policy_activation_request"](ns["DB_PATH"], request_id)
        if not approval:
            raise KeyError(request_id)
        target = ns["get_policy_version"](ns["DB_PATH"], str(approval["policy_id"]))
        if not target:
            raise KeyError(str(approval["policy_id"]))
        active = self.ensure_policy_registry()
        if str(active.get("policy_id") or "") != str(approval.get("active_policy_id_at_request") or ""):
            raise ns["ConcurrencyError"]("요청 이후 활성 정책이 변경되었습니다. 영향분석 후 다시 요청하세요.")
        active_policy = ns["parse_policy_text"](str(active["content_yaml"]))
        candidate_policy = ns["parse_policy_text"](str(target["content_yaml"]))
        findings = ns["list_findings"](ns["DB_PATH"])
        fresh_impact = ns["compare_policy_impact"](findings, active_policy, candidate_policy)
        requested_fingerprint = str((approval.get("impact") or {}).get("dataset_fingerprint") or "")
        if requested_fingerprint and requested_fingerprint != str(fresh_impact.get("dataset_fingerprint") or ""):
            raise ns["ConcurrencyError"]("활성화 요청 이후 취약점 데이터가 변경되었습니다. 영향분석 후 다시 요청하세요.")
        scored = [
            ns["score_with_policy"](row, candidate_policy, policy_id=str(target["policy_id"]))
            for row in findings
            if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"
        ]
        return approval, target, scored

    def refresh_intelligence(
        self, *, actor: str, context: Any | None = None,
        rescore_callback: Any, queue_webhook_callback: Any,
    ) -> dict[str, Any]:
        ns = self.namespace
        runtime = self.runtime_context(context)
        db_path = runtime.get("DB_PATH")
        findings = [
            row for row in self.runtime_service(runtime, "list_findings")(db_path)
            if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"
        ]
        cves = sorted({str(row.get("cve_id", "")).upper() for row in findings if row.get("cve_id")})
        if not cves:
            raise ValueError("갱신할 CVE가 없습니다.")
        updates: dict[str, dict[str, Any]] = {cve: {} for cve in cves}
        sources: list[str] = []
        errors: list[str] = []
        intel_options = {
            "timeout": int(runtime.get("INTEL_TIMEOUT_SECONDS", 30)),
            "retries": int(runtime.get("INTEL_RETRIES", 3)),
            "max_response_bytes": int(runtime.get("INTEL_MAX_RESPONSE_BYTES", 8 * 1024 * 1024)),
            "allow_private_networks": bool(runtime.get("OUTBOUND_ALLOW_PRIVATE_NETWORKS", False)),
            "host_allowlist": str(runtime.get("OUTBOUND_HOST_ALLOWLIST", "") or ""),
        }
        try:
            kev_catalog = call_with_supported_options(
                self.runtime_service(runtime, "fetch_kev_catalog"), **intel_options
            )
            for cve in cves:
                updates[cve]["kev"] = cve in kev_catalog
            sources.append("CISA KEV")
        except ns["IntelligenceError"] as exc:
            errors.append(str(exc))
        try:
            epss_map = call_with_supported_options(
                self.runtime_service(runtime, "fetch_epss"), cves, **intel_options
            )
            for cve, values in epss_map.items():
                updates[cve]["epss"] = values.get("epss")
                updates[cve]["epss_percentile"] = values.get("percentile")
            sources.append("FIRST EPSS")
        except ns["IntelligenceError"] as exc:
            errors.append(str(exc))
        updates = {cve: values for cve, values in updates.items() if values}
        if not updates:
            raise RuntimeError(" / ".join(errors) or "위협정보를 갱신하지 못했습니다.")
        changed = self.runtime_service(runtime, "bulk_update_intel")(
            db_path, updates, intel_source=" + ".join(sources), actor=actor
        )
        rescored = rescore_callback(audit=False, actor=actor, context=runtime)
        result = {"changed_rows": changed, "rescored": rescored, "sources": sources, "errors": errors}
        queue_webhook_callback("intelligence.refreshed", result, actor, context=runtime)
        return result

    def score_row(
        self, row: dict[str, Any], policy: dict[str, Any] | None = None,
        *, policy_id: str | None = None,
    ) -> dict[str, Any]:
        ns = self.namespace
        today = date.today().isoformat()
        if not str(row.get("first_seen_at") or "").strip():
            row["first_seen_at"] = today
        if not str(row.get("first_scored_at") or "").strip():
            row["first_scored_at"] = today
        if policy is None:
            record = self.active_policy_record()
            policy = ns["parse_policy_text"](str(record["content_yaml"])) if record else self.policy()
            policy_id = str(record["policy_id"]) if record else policy_id
        result = ns["prioritize_finding"](row, policy)
        row.update({
            "score": result.score,
            "threat_score": result.threat_score,
            "asset_context_score": result.asset_context_score,
            "remediation_urgency_score": result.remediation_urgency_score,
            "decision": result.decision,
            "decision_label": result.decision_label,
            "sla_days": result.sla_days,
            "target_date": result.target_date,
            "mitigation_required": int(result.mitigation_required),
            "reasons": " | ".join(result.reasons),
            "policy_version": result.policy_version,
            "policy_id": policy_id or str(row.get("policy_id") or ""),
            "last_scored_at": today,
        })
        return row

    def rescore_all(
        self, *, audit: bool = True, actor: str = "local-user",
        context: Any | None = None, score_callback: Any,
    ) -> int:
        ns = self.namespace
        runtime = self.runtime_context(context)
        db_path = runtime.get("DB_PATH")
        rows = [
            row for row in self.runtime_service(runtime, "list_findings")(db_path)
            if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"
        ]
        if not rows:
            return 0
        record = self.ensure_policy_registry(runtime)
        policy = ns["parse_policy_text"](str(record["content_yaml"]))
        self.runtime_service(runtime, "update_scores")(
            db_path, [score_callback(row, policy, policy_id=str(record["policy_id"])) for row in rows],
            actor=actor, audit=audit,
        )
        return len(rows)

    def enqueue_simple_job(
        self, request: Request, job_type: str, *, idempotency_key: str | None = None,
        role_callback: Any, require_role_callback: Any,
        actor_callback: Any, maintenance_settings_callback: Any,
    ) -> dict[str, Any]:
        ns = self.namespace
        job_type = str(job_type or "").upper()
        require_role_callback(request, role_callback(job_type))
        payload: dict[str, Any] = {}
        if job_type == "MAINTENANCE":
            payload["settings"] = maintenance_settings_callback()
        return ns["create_background_job"](
            ns["DB_PATH"], job_type=job_type, payload=payload,
            requested_by=actor_callback(request),
            priority=10 if job_type == "WEBHOOK_DELIVERY" else (8 if job_type == "RECOVERY_BACKUP" else 0),
            max_attempts=ns["JOB_MAX_ATTEMPTS"], idempotency_key=idempotency_key,
            idempotency_request={"job_type": job_type, "payload": payload},
            idempotency_retention_days=ns["IDEMPOTENCY_RETENTION_DAYS"],
        )
