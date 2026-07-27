from __future__ import annotations

"""Application startup and deterministic shutdown orchestration."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.application_runtime_common import Namespace, runtime_callback
from app.core.auth import parse_accounts, parse_api_tokens
from app.core.context import get_application_context
from app.core.transactions import transaction_scope
from app.services.lifecycle_runtime import LifecycleSupervisor, coordination_db_path


@asynccontextmanager
async def lifespan_scoped(application: FastAPI, *, namespace: Namespace):
    context = get_application_context(application)
    refresh_router_dependencies = runtime_callback(namespace, "_refresh_router_dependencies")
    runtime_service = runtime_callback(namespace, "_runtime_service")
    refresh_router_dependencies(context)

    users_json = str(context.get("AUTH_USERS_JSON", "") or "")
    tokens_json = str(context.get("AUTH_API_TOKENS_JSON", "") or "")
    legacy_user = str(context.get("AUTH_USER", "") or "")
    legacy_password = str(context.get("AUTH_PASSWORD", "") or "")
    allow_local_fallback = bool(context.get("ALLOW_LOCAL_ADMIN_FALLBACK", False))
    accounts = parse_accounts(users_json) if users_json else {}
    tokens = parse_api_tokens(tokens_json) if tokens_json else {}
    if bool(legacy_user) != bool(legacy_password):
        raise RuntimeError("VULNFLOW_AUTH_USER와 VULNFLOW_AUTH_PASSWORD는 함께 설정해야 합니다.")
    if not accounts and not tokens and not (legacy_user and legacy_password) and not allow_local_fallback:
        raise RuntimeError(
            "인증 계정 또는 API token이 없습니다. 로컬 loopback 전용 개발 실행에서만 "
            "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=1을 명시하세요."
        )

    signing = runtime_callback(namespace, "_signing_config")(context)
    audit_key_id, audit_key = signing.active("audit")
    signing.active("backup")
    endpoints = runtime_service(context, "parse_webhook_endpoints")(
        str(context.get("WEBHOOKS_JSON", "") or ""),
        allow_insecure_http=bool(context.get("WEBHOOK_ALLOW_INSECURE_HTTP")),
    )
    context.set("WEBHOOK_ENDPOINTS", endpoints)
    refresh_router_dependencies(context)

    scanner_mode = str(context.get("EVIDENCE_SCANNER_MODE"))
    if scanner_mode not in {"builtin", "clamscan", "disabled"}:
        raise RuntimeError(
            "VULNFLOW_EVIDENCE_SCANNER_MODE는 builtin, clamscan, disabled 중 하나여야 합니다."
        )

    db_path = context.get("DB_PATH")
    evidence_dir = Path(context.get("EVIDENCE_DIR"))
    export_dir = Path(context.get("EXPORT_DIR"))
    runtime_service(context, "init_db")(db_path)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    runtime_service(context, "reconcile_export_artifacts")(
        db_path, export_dir, actor="system-startup"
    )
    evidence_integrity = runtime_service(context, "verify_evidence_store")(
        db_path, evidence_dir
    )
    if not evidence_integrity.get("valid"):
        raise RuntimeError("증거 저장소 무결성 검증 실패")
    integrity = runtime_service(context, "verify_audit_integrity")(
        db_path, signing_keys=signing.keys
    )
    if not integrity.get("valid"):
        raise RuntimeError(
            "감사 체인 무결성 검증 실패: " + "; ".join(integrity.get("issues") or [])
        )

    if bool(context.get("CLUSTER_COORDINATION_ENABLED")):
        runtime_service(context, "init_coordination_db")(coordination_db_path(context))
    runtime_callback(namespace, "_ensure_policy_registry")(context)
    sample_path = Path(context.get("SAMPLE_PATH"))
    if runtime_service(context, "count_findings")(db_path) == 0 and sample_path.exists():
        runtime_service(context, "upsert_findings")(
            db_path,
            runtime_callback(namespace, "_load_sample_rows")(sample_path),
            actor="system-seed",
        )
    runtime_callback(namespace, "rescore_all")(audit=False, context=context)

    if audit_key:
        current_integrity = runtime_service(context, "verify_audit_integrity")(
            db_path, signing_keys=signing.keys
        )
        checkpoints = current_integrity.get("checkpoints") or []
        latest = checkpoints[-1] if checkpoints else {}
        if (
            not checkpoints
            or int(latest.get("chain_seq") or -1)
            != int(current_integrity.get("last_seq") or 0)
            or str(latest.get("key_id") or "") != str(audit_key_id or "")
        ):
            runtime_service(context, "create_audit_checkpoint")(
                db_path,
                signing_key=audit_key,
                signing_key_id=audit_key_id,
                actor="system-startup",
            )

    supervisor = LifecycleSupervisor(context)
    context.set("LIFECYCLE_SUPERVISOR", supervisor)
    supervisor.start()
    try:
        yield
    finally:
        shutdown_snapshot = await supervisor.stop()
        if shutdown_snapshot.get("shutdown_timed_out"):
            context.logger.error(
                "lifecycle shutdown exceeded deadline",
                extra={
                    "runtime_id": context.router_runtime_id,
                    "pending_task_names": sorted(
                        shutdown_snapshot.get("pending_task_stacks", {})
                    ),
                },
            )


@asynccontextmanager
async def application_lifespan(application: FastAPI, *, namespace: Namespace):
    context = get_application_context(application)
    assert context.transaction_registry is not None
    with transaction_scope(context.transaction_registry):
        async with lifespan_scoped(application, namespace=namespace):
            yield
