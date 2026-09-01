from __future__ import annotations
from app.ui_i18n import format_items, translate_message

import asyncio
import csv
from contextlib import asynccontextmanager, contextmanager
import hmac
import io
import json
import os
import re
import secrets
import socket
import tempfile
import time
import uuid
from datetime import date
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from app.api.models import *  # noqa: F403 - route annotations and compatibility exports
from starlette.background import BackgroundTask
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.application_services import install_application_services
from app.endpoint_workflows import EndpointWorkflows, NOTICE_MESSAGES, STATUS_TRANSITIONS
from app.application_lifespan import (
    application_lifespan,
    lifespan_scoped as runtime_lifespan_scoped,
)
from app.http_runtime import (
    friendly_http_error as runtime_friendly_http_error,
    local_security as runtime_local_security,
    local_security_scoped as runtime_local_security_scoped,
)
from app.services.request_processing import (
    active as _active,
    bounded_text as _bounded_text,
    csv_safe as _csv_safe,
    date_text as _date_text,
    export_filters_from_values as _export_filters_from_values,
    filter_findings as _filter_findings,
    job_role as _job_role,
    normalize_finding_row,
    number as _number,
    parse_assets_csv as _parse_assets_csv,
    parse_findings_csv,
    prepare_findings_rows,
    public_job as _public_job,
)
from app.services.view_models import (
    campaign_member_ids,
    evidence_with_custody,
)
from app.core.settings import *  # noqa: F403 - compatibility re-export for tests and operators

install_application_services(globals())
_ENDPOINT_WORKFLOWS = EndpointWorkflows(globals())


METRICS = Metrics()
LOGGER = configure_json_logging(LOG_LEVEL)
WEBHOOK_ENDPOINTS: dict[str, Any] = {}
_COORDINATION_STATE: dict[str, Any] = {"scheduler_token": None, "is_leader": not CLUSTER_COORDINATION_ENABLED, "last_heartbeat": ""}


def _runtime_context(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.runtime_context(context)



def _runtime_value(context: "ApplicationContext | None", name: str, fallback: Any = None) -> Any:
    return _ENDPOINT_WORKFLOWS.runtime_value(context, name, fallback)



def _runtime_service(context: "ApplicationContext | None", name: str):
    return _ENDPOINT_WORKFLOWS.runtime_service(context, name)


def _signing_config(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.signing_config(context)



def _audit_signing(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.audit_signing(context)



def _integrity_proof_signing_config(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.ed25519_config("proof", context)



def _integrity_witness_signing_config(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.ed25519_config("witness", context)



def _integrity_transparency_signing_config(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.ed25519_config("transparency", context)



def _integrity_mirror_signing_config(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.ed25519_config("mirror", context)



def _backup_signing(context: "ApplicationContext | None" = None):
    return _ENDPOINT_WORKFLOWS.backup_signing(context)




def _create_asset_merge_recovery_bundle(request_id: str, actor: str) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.create_asset_merge_recovery_bundle(request_id, actor)


# Workflow status and operator notices are owned by app.endpoint_workflows.
def _load_sample_rows(path: Path) -> list[dict[str, Any]]:
    return _ENDPOINT_WORKFLOWS.load_sample_rows(path, normalize_row)


def _ensure_policy_registry(context: "ApplicationContext | None" = None) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.ensure_policy_registry(context)




def _active_policy_record() -> dict[str, Any] | None:
    return _ENDPOINT_WORKFLOWS.active_policy_record()



def _policy() -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.policy()



def _actor(request: Request) -> str:
    return _ENDPOINT_WORKFLOWS.actor(request)



def _new_csrf() -> str:
    return _ENDPOINT_WORKFLOWS.new_csrf()



def _verify_csrf(request: Request, form_token: str) -> None:
    _ENDPOINT_WORKFLOWS.verify_csrf(request, form_token)



def _principal(request: Request):
    return _ENDPOINT_WORKFLOWS.principal(request)



def _require_api_token(request: Request) -> None:
    _ENDPOINT_WORKFLOWS.require_api_token(request)



def _queue_webhook(
    event_type: str, payload: dict[str, Any], actor: str,
    context: "ApplicationContext | None" = None,
    idempotency_key: str | None = None,
) -> list[str]:
    return _ENDPOINT_WORKFLOWS.queue_webhook(
        event_type, payload, actor, context=context, idempotency_key=idempotency_key
    )




def _require_role(request: Request, minimum: str) -> None:
    _ENDPOINT_WORKFLOWS.require_role(request, minimum)



def _maintenance_settings(context: "ApplicationContext | None" = None) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.maintenance_settings(context)




def _purge_completed_jobs(context: "ApplicationContext | None" = None) -> int:
    return _ENDPOINT_WORKFLOWS.purge_completed_jobs(context)




def _prepare_policy_activation(request_id: str) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    return _ENDPOINT_WORKFLOWS.prepare_policy_activation(request_id)




def _coordination_db_path(context: "ApplicationContext | None" = None) -> Path:
    return context_coordination_db_path(context or APPLICATION_CONTEXT)



def _instance_capabilities(context: "ApplicationContext | None" = None) -> list[str]:
    return context_instance_capabilities(context or APPLICATION_CONTEXT)



def _cluster_snapshot(context: "ApplicationContext | None" = None) -> dict[str, Any]:
    return context_cluster_snapshot(context or APPLICATION_CONTEXT)



def _coordination_tick(context: "ApplicationContext | None" = None) -> dict[str, Any]:
    return context_coordination_tick(context or APPLICATION_CONTEXT)



async def _coordination_loop(context: "ApplicationContext | None" = None) -> None:
    await context_coordination_loop(context or APPLICATION_CONTEXT)



def _is_scheduler_leader(context: "ApplicationContext | None" = None) -> bool:
    return context_is_scheduler_leader(context or APPLICATION_CONTEXT)



def _restore_in_progress(context: "ApplicationContext | None" = None) -> bool:
    return bind_operation_guard(context or APPLICATION_CONTEXT).restore_in_progress()



@contextmanager
def _exclusive_operation(
    lease_name: str, purpose: str, *, context: "ApplicationContext | None" = None
):
    with bind_operation_guard(context or APPLICATION_CONTEXT).exclusive_operation(lease_name, purpose) as lease:
        yield lease


async def _maintenance_loop(context: "ApplicationContext | None" = None) -> None:
    await context_maintenance_loop(context or APPLICATION_CONTEXT)



async def _webhook_loop(context: "ApplicationContext | None" = None) -> None:
    await context_webhook_loop(context or APPLICATION_CONTEXT)



async def _backup_loop(context: "ApplicationContext | None" = None) -> None:
    await context_backup_loop(context or APPLICATION_CONTEXT)



def _refresh_intelligence_operation(
    *, actor: str, context: "ApplicationContext | None" = None
) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.refresh_intelligence(
        actor=actor, context=context, rescore_callback=rescore_all,
        queue_webhook_callback=_queue_webhook,
    )




def _execute_background_job(
    job: dict[str, Any], *, worker_id: str, context: "ApplicationContext | None" = None
) -> dict[str, Any]:
    runtime = context or APPLICATION_CONTEXT
    return execute_background_job_with_project_scope(
        runtime,
        job,
        worker_id=worker_id,
        executor=execute_background_job_for_context,
    )



async def _job_worker_loop(context: "ApplicationContext") -> None:
    await context_job_worker_loop(context)



templates = Jinja2Templates(directory=APP_DIR / "templates")
templates.env.filters["ui_message"] = translate_message
templates.env.filters["ui_items"] = format_items
templates.env.globals["app_version"] = CURRENT_APP_VERSION


@asynccontextmanager
async def _lifespan_scoped(application: FastAPI):
    async with runtime_lifespan_scoped(application, namespace=globals()):
        yield


@asynccontextmanager
async def lifespan(application: FastAPI):
    async with application_lifespan(application, namespace=globals()):
        yield


async def _local_security_scoped(
    request: Request, call_next, context: "ApplicationContext"
):
    return await runtime_local_security_scoped(
        request, call_next, context, namespace=globals()
    )


async def local_security(request: Request, call_next):
    return await runtime_local_security(request, call_next, namespace=globals())


async def friendly_http_error(request: Request, exc: HTTPException):
    return await runtime_friendly_http_error(request, exc)


def score_row(
    row: dict[str, Any], policy: dict[str, Any] | None = None, *, policy_id: str | None = None
) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.score_row(row, policy, policy_id=policy_id)



def normalize_row(row: dict[str, Any], index: int, scanner_source: str = "manual") -> dict[str, Any]:
    """Compatibility wrapper over the explicit request-processing service."""
    return normalize_finding_row(
        row, index, scanner_source=scanner_source, cve_pattern=CVE_RE, score_callback=score_row
    )


def _parse_findings_csv(
    content: bytes, *, scanner_source: str, allow_empty: bool = False
) -> list[dict[str, Any]]:
    return parse_findings_csv(
        content, scanner_source=scanner_source, allow_empty=allow_empty, db_path=DB_PATH,
        list_findings_fn=list_findings, list_assets_fn=list_assets,
        normalize_callback=lambda raw, idx, source: normalize_row(raw, idx, scanner_source=source),
        rescore_callback=score_row,
    )



def _evaluate_finding_import(
    content: bytes,
    *,
    filename: str,
    format_hint: str,
    mapping: dict[str, str] | None,
    scanner_source: str,
    allow_empty: bool = False,
) -> dict[str, Any]:
    parsed = parse_import_file(content, filename=filename, format_hint=format_hint)
    active_mapping = dict(parsed["mapping"] if mapping is None else mapping)
    mapped_rows, mapped_source_rows, mapping_errors = map_import_rows(
        parsed["rows"], parsed["source_rows"], active_mapping
    )
    prepared = prepare_findings_rows(
        mapped_rows, scanner_source=scanner_source, allow_empty=allow_empty, db_path=DB_PATH,
        list_findings_fn=list_findings, list_assets_fn=list_assets,
        normalize_callback=lambda raw, idx, source: normalize_row(raw, idx, scanner_source=source),
        rescore_callback=score_row, source_rows=mapped_source_rows, collect_errors=True,
    )
    errors = list(parsed.get("source_errors", [])) + list(mapping_errors) + list(prepared["errors"])
    return {
        **parsed,
        "mapping": active_mapping,
        "mapped_row_count": len(mapped_rows),
        "valid_rows": prepared["rows"],
        "errors": errors,
    }

def rescore_all(
    *, audit: bool = True, actor: str = "local-user",
    context: "ApplicationContext | None" = None,
) -> int:
    return _ENDPOINT_WORKFLOWS.rescore_all(
        audit=audit, actor=actor, context=context, score_callback=score_row
    )




def _campaign_member_ids(*, finding_ids: list[str], cve_id: str = "") -> list[str]:
    return campaign_member_ids(
        DB_PATH, finding_ids=finding_ids, cve_id=cve_id, list_findings_fn=list_findings
    )


def _evidence_with_custody(*, finding_id: str) -> list[dict[str, Any]]:
    return evidence_with_custody(
        DB_PATH, finding_id=finding_id, list_evidence_artifacts_fn=list_evidence_artifacts,
        list_custody_events_fn=list_evidence_custody_events,
        verify_custody_chain_fn=verify_evidence_custody_chain,
    )


def _enqueue_simple_job(
    request: Request, job_type: str, *, idempotency_key: str | None = None
) -> dict[str, Any]:
    return _ENDPOINT_WORKFLOWS.enqueue_simple_job(
        request, job_type, idempotency_key=idempotency_key,
        role_callback=_job_role, require_role_callback=_require_role,
        actor_callback=_actor, maintenance_settings_callback=_maintenance_settings,
    )














# Application assembly is delayed until every helper is available.
from app.core.context import ApplicationContext, RequestRuntime, get_application_context
from app.core.runtime import RuntimeSettings, ServiceContainer
from app.factory import create_application
from app.application_runtime_common import prepare_application_context
from app.routers import refresh_runtime_dependencies as _refresh_router_dependencies

APPLICATION_CONTEXT = ApplicationContext(
    namespace=globals(),
    templates=templates,
    metrics=METRICS,
    logger=LOGGER,
    coordination_state=_COORDINATION_STATE,
    settings=RuntimeSettings.from_namespace(globals()),
    services=ServiceContainer.from_namespace(globals()),
)


def create_app(
    *,
    context: ApplicationContext | None = None,
    setting_overrides: dict[str, Any] | None = None,
    service_overrides: dict[str, Any] | None = None,
) -> FastAPI:
    """Build a VulnFlow application through the explicit assembly factory.

    The module-level process app uses ``APPLICATION_CONTEXT``. Additional app
    instances receive a shallow namespace copy so construction does not replace
    the historical ``app.main.app`` compatibility export.
    """
    if context is not None and (setting_overrides or service_overrides):
        raise ValueError("context와 dependency override를 동시에 지정할 수 없습니다.")
    runtime_context = context or APPLICATION_CONTEXT.clone(
        namespace=dict(globals()),
        setting_overrides=setting_overrides,
        service_overrides=service_overrides,
        coordination_state=dict(_COORDINATION_STATE),
    )
    prepare_application_context(runtime_context)
    bind_operation_guard(runtime_context)
    return create_application(
        context=runtime_context,
        version=CURRENT_APP_VERSION,
        lifespan=lifespan,
        middleware=local_security,
        http_exception_handler=friendly_http_error,
        app_dir=APP_DIR,
    )


app = create_app(context=APPLICATION_CONTEXT)
_ROUTE_EXPORTS = APPLICATION_CONTEXT.route_exports
