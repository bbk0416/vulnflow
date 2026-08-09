from __future__ import annotations

"""Application startup and deterministic shutdown orchestration."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.application_runtime_common import Namespace, runtime_callback
from app.core.auth import parse_api_tokens
from app.core.context import get_application_context
from app.core.transactions import transaction_scope
from app.routers import release_runtime_application
from app.services.lifecycle_runtime import LifecycleSupervisor, coordination_db_path
from app.services.project_startup import initialize_project_stores
from app.services.runtime_dependency_policy import enforce_runtime_dependencies
from app.services.security_profile import enforce_security_profile
from app.services.storage_layout import prepare_split_storage


@asynccontextmanager
async def lifespan_scoped(application: FastAPI, *, namespace: Namespace):
    context = get_application_context(application)
    refresh_router_dependencies = runtime_callback(namespace, "_refresh_router_dependencies")
    context.app = application
    context.namespace["app"] = application
    runtime_service = runtime_callback(namespace, "_runtime_service")
    refresh_router_dependencies(context)

    users_json = str(context.get("AUTH_USERS_JSON", "") or "")
    tokens_json = str(context.get("AUTH_API_TOKENS_JSON", "") or "")
    legacy_user = str(context.get("AUTH_USER", "") or "")
    legacy_password = str(context.get("AUTH_PASSWORD", "") or "")
    demo_mode = bool(context.get("DEMO_MODE", False))
    allow_local_fallback = bool(context.get("ALLOW_LOCAL_ADMIN_FALLBACK", False))

    control_db = Path(context.get("CONTROL_DB_PATH"))
    default_db = Path(context.get("DEFAULT_PROJECT_DB_PATH"))
    evidence_dir = Path(context.get("DEFAULT_EVIDENCE_DIR"))
    export_dir = Path(context.get("DEFAULT_EXPORT_DIR"))
    preparation = prepare_split_storage(
        control_database=control_db,
        default_project_database=default_db,
        legacy_database=Path(context.get("LEGACY_DB_PATH")),
        data_directory=Path(context.get("DATA_DIR")),
        directory_migrations=(
            (Path(context.get("LEGACY_EVIDENCE_DIR")), evidence_dir),
            (Path(context.get("LEGACY_EXPORT_DIR")), export_dir),
            (
                Path(context.get("LEGACY_IMPORT_PREVIEW_DIR")),
                Path(context.get("DEFAULT_IMPORT_PREVIEW_DIR")),
            ),
            (Path(context.get("LEGACY_RECOVERY_DIR")), Path(context.get("DEFAULT_RECOVERY_DIR"))),
        ),
        init_db_fn=runtime_service(context, "init_db"),
    )
    context.set("STORAGE_PREPARATION", preparation.as_dict())
    evidence_dir.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)

    if users_json or legacy_user or legacy_password:
        raise RuntimeError(
            "평문 환경변수 사용자 인증은 제거되었습니다. "
            "python -m scripts.manage_users --db <제어DB경로> create 명령으로 DB 사용자 계정을 만드세요."
        )
    tokens = parse_api_tokens(tokens_json) if tokens_json else {}
    profile_report = enforce_security_profile(
        context.settings.as_dict() if context.settings is not None else context.namespace,
        tokens=tokens,
    )
    context.set("SECURITY_PROFILE_REPORT", profile_report.as_dict())
    dependency_report = enforce_runtime_dependencies(
        policy=str(context.get("RUNTIME_DEPENDENCY_POLICY", "off") or "off"),
    )
    context.set("RUNTIME_DEPENDENCY_REPORT", dependency_report.as_dict())
    for finding in dependency_report.findings:
        context.logger.warning(
            "runtime dependency finding",
            extra={
                "code": finding.code,
                "package": finding.package,
                "expected": finding.expected,
                "actual": finding.actual,
            },
        )
    if not profile_report.passed:
        for finding in profile_report.findings:
            context.logger.warning(
                "security profile finding",
                extra={"profile": profile_report.profile, "code": finding.code},
            )
    if allow_local_fallback and not demo_mode:
        raise RuntimeError(
            "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK은 VULNFLOW_DEMO_MODE=1인 로컬 데모에서만 사용할 수 있습니다."
        )
    active_users = int(runtime_service(context, "count_active_users")(control_db))
    if active_users == 0 and not tokens and not allow_local_fallback:
        raise RuntimeError(
            "활성 사용자 계정 또는 API token이 없습니다. 먼저 "
            "python -m scripts.manage_users --db <제어DB경로> create --username admin --role admin 명령을 실행하세요."
        )

    signing = runtime_callback(namespace, "_signing_config")(context)
    signing.active("audit")
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

    startup = initialize_project_stores(
        context,
        signing=signing,
        ensure_policy_registry=runtime_callback(namespace, "_ensure_policy_registry"),
        load_sample_rows=runtime_callback(namespace, "_load_sample_rows"),
        rescore_all=runtime_callback(namespace, "rescore_all"),
    )
    supervisor = LifecycleSupervisor(context)
    context.set("LIFECYCLE_SUPERVISOR", supervisor)

    if bool(context.get("CLUSTER_COORDINATION_ENABLED")):
        runtime_service(context, "init_coordination_db")(coordination_db_path(context))
    if int(startup.get("healthy_count") or 0) > 0:
        supervisor.start()
    else:
        context.coordination_state["is_leader"] = False
        context.coordination_state["scheduler_token"] = None
        context.logger.critical(
            "all active projects entered read-only recovery mode",
            extra={"degraded_count": startup.get("degraded_count", 0)},
        )

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
    try:
        with transaction_scope(context.transaction_registry):
            async with lifespan_scoped(application, namespace=namespace):
                yield
    finally:
        release_runtime_application(context)
