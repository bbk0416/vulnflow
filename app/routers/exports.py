from __future__ import annotations

"""Domain routes extracted from :mod:`app.main`.

The route module is intentionally dependency-injected by ``app.routers`` so the
historical compatibility surface in ``app.main`` remains available without creating
internal import cycles.
"""

from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.api.models import *  # noqa: F403 - route request models

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = ('exports_page', 'exports_findings_queue', 'export_artifact_download', 'export_artifact_expire', 'export_artifact_pin', 'export_storage_cleanup', 'export_csv', 'export_report', 'export_backup', 'restore_backup', 'api_exports', 'api_exports_findings', 'api_export_detail', 'api_export_download', 'api_export_expire', 'api_export_pin', 'api_export_storage_cleanup')

@router.get("/exports", response_class=HTMLResponse)
def exports_page(request: Request, status: str = "", notice: str = ""):
    _require_role(request, "viewer")
    try:
        artifacts = list_export_artifacts(DB_PATH, status=status, limit=500)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(
        request=request,
        name="exports.html",
        context={
            "artifacts": artifacts,
            "storage": export_storage_status(
                DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES
            ),
            "status": str(status or "").strip().upper(),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/exports/findings")
def exports_findings_queue(
    request: Request,
    csrf_token: str = Form(...),
    decision: str = Form(""),
    status: str = Form(""),
    query: str = Form(""),
    overdue: bool = Form(False),
    exception: str = Form(""),
    record_state: str = Form("ALL"),
    scanner_source: str = Form(""),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        filters = _export_filters_from_values(
            decision=decision, status=status, query=query, overdue=overdue,
            exception=exception, record_state=record_state, scanner_source=scanner_source,
        )
        create_background_job(
            DB_PATH,
            job_type="FINDINGS_EXPORT",
            payload={"filters": filters},
            requested_by=_actor(request),
            max_attempts=JOB_MAX_ATTEMPTS,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/exports?notice=export_queued", status_code=303)

@router.get("/exports/{artifact_id}/download")
def export_artifact_download(request: Request, artifact_id: str):
    _require_role(request, "viewer")
    artifact = get_export_artifact(DB_PATH, artifact_id)
    if not artifact:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.")
    if str(artifact.get("status") or "") != "READY":
        raise HTTPException(410, "다운로드 가능한 내보내기 산출물이 아닙니다.")
    verification = verify_export_artifact(EXPORT_DIR, artifact)
    if not verification.get("valid"):
        mark_export_artifact_corrupt(
            DB_PATH, artifact_id, actor=_actor(request), reason=str(verification.get("reason") or "invalid")
        )
        raise HTTPException(409, "내보내기 파일 무결성 검증에 실패했습니다.")
    try:
        artifact = record_export_download(DB_PATH, artifact_id, actor=_actor(request))
    except ValueError as exc:
        raise HTTPException(410, str(exc)) from exc
    path = resolve_export_artifact_path(EXPORT_DIR, artifact)
    return FileResponse(
        path,
        filename=str(artifact.get("download_filename") or "vulnflow_findings.csv"),
        media_type=str(artifact.get("content_type") or "text/csv"),
        headers={"X-Content-SHA256": str(artifact.get("sha256") or ""), "Cache-Control": "no-store"},
    )

@router.post("/exports/{artifact_id}/expire")
def export_artifact_expire(request: Request, artifact_id: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        expire_export_artifact(DB_PATH, EXPORT_DIR, artifact_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.") from exc
    return RedirectResponse(url="/exports?notice=export_expired", status_code=303)

@router.post("/exports/{artifact_id}/pin")
def export_artifact_pin(
    request: Request, artifact_id: str, pinned: bool = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        set_export_artifact_pinned(DB_PATH, artifact_id, pinned=bool(pinned), actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    notice = "export_pinned" if pinned else "export_unpinned"
    return RedirectResponse(url=f"/exports?notice={notice}", status_code=303)

@router.post("/exports/storage/cleanup")
def export_storage_cleanup(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        enforce_export_storage_budget(
            DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES,
            actor=_actor(request),
        )
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse(url="/exports?notice=export_storage_cleaned", status_code=303)

@router.get("/export/findings.csv")
def export_csv(
    decision: str = "",
    status: str = "",
    record_state: str = "ALL",
    scanner_source: str = "",
):
    filters = {
        "decision": str(decision or "").strip(),
        "status": str(status or "").strip(),
        "record_state": str(record_state or "ALL").strip().upper(),
        "scanner_source": str(scanner_source or "").strip(),
    }
    return StreamingResponse(
        stream_findings_csv(DB_PATH, filters=filters),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=vulnflow_prioritized_findings.csv",
            "Cache-Control": "no-store",
            "X-VulnFlow-Export-Mode": "transactional-stream",
        },
    )

@router.get("/export/report.html")
def export_report():
    return Response(
        generate_html_report(list_findings(DB_PATH)),
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=vulnflow_report.html"},
    )

@router.get("/export/backup.sqlite3")
def export_backup(request: Request):
    _require_role(request, "admin")
    handle = tempfile.NamedTemporaryFile(prefix="vulnflow_backup_", suffix=".sqlite3", delete=False)
    handle.close()
    backup_database(DB_PATH, handle.name)
    return FileResponse(
        handle.name,
        filename="vulnflow_backup.sqlite3",
        media_type="application/vnd.sqlite3",
        background=BackgroundTask(lambda: os.unlink(handle.name) if os.path.exists(handle.name) else None),
    )

@router.post("/restore-backup")
async def restore_backup(
    request: Request,
    file: UploadFile = File(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if confirmation.strip() != "RESTORE":
        raise HTTPException(400, "복원 확인란에 RESTORE를 입력해야 합니다.")
    filename = (file.filename or "").lower()
    if not filename.endswith((".sqlite3", ".sqlite", ".db")):
        raise HTTPException(400, "SQLite 백업 파일(.sqlite3, .sqlite, .db)만 지원합니다.")
    content = await file.read(MAX_BACKUP_BYTES + 1)
    if len(content) > MAX_BACKUP_BYTES:
        raise HTTPException(413, "백업 파일 크기는 최대 50MB입니다.")
    if not content.startswith(b"SQLite format 3\x00"):
        raise HTTPException(400, "SQLite 파일 헤더가 올바르지 않습니다.")
    temp_path = ""
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vulnflow_restore_", suffix=".sqlite3", delete=False)
        temp_path = handle.name
        handle.write(content)
        handle.close()
        backup_summary = validate_database_file(temp_path)
        if int(backup_summary.get("evidence_count") or 0) > 0:
            raise ValueError("증거 파일이 포함된 데이터베이스는 복구 번들 ZIP으로 복원해야 합니다.")
        with _exclusive_operation(RESTORE_LEASE_NAME, "데이터베이스 복원"):
            if count_active_background_jobs(DB_PATH) > 0:
                raise ConcurrencyError("실행 또는 대기 중인 백그라운드 작업이 있어 복원할 수 없습니다.")
            if count_cluster_write_activities(_coordination_db_path()) > 0:
                raise ConcurrencyError("처리 중인 쓰기 요청이 있어 복원할 수 없습니다.")
            restore_database(DB_PATH, temp_path, actor=_actor(request))
            rescore_all(audit=False, actor=_actor(request))
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return RedirectResponse(url="/?notice=restore_ok", status_code=303)

@router.get("/api/v1/exports")
def api_exports(request: Request, status: str = "", limit: int = 200):
    _require_role(request, "viewer")
    try:
        items = list_export_artifacts(DB_PATH, status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "count": len(items), "items": items,
        "storage": export_storage_status(
            DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES
        ),
    }

@router.post("/api/v1/exports/findings")
def api_exports_findings(
    request: Request, payload: ApiFindingsExport,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        filters = _export_filters_from_values(
            decision=payload.decision,
            status=payload.status,
            query=payload.query,
            overdue=payload.overdue,
            exception=payload.exception,
            record_state=payload.record_state,
            scanner_source=payload.scanner_source,
        )
        return create_background_job(
            DB_PATH,
            job_type="FINDINGS_EXPORT",
            payload={"filters": filters},
            requested_by=_actor(request),
            max_attempts=JOB_MAX_ATTEMPTS,
            idempotency_key=idempotency_key,
            idempotency_request={"job_type": "FINDINGS_EXPORT", "filters": filters},
            idempotency_retention_days=IDEMPOTENCY_RETENTION_DAYS,
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/exports/{artifact_id}")
def api_export_detail(request: Request, artifact_id: str):
    _require_role(request, "viewer")
    artifact = get_export_artifact(DB_PATH, artifact_id)
    if not artifact:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.")
    verification = verify_export_artifact(EXPORT_DIR, artifact) if artifact.get("status") == "READY" else {"valid": False, "reason": "not_ready"}
    return artifact | {"verification": verification}

@router.get("/api/v1/exports/{artifact_id}/download")
def api_export_download(request: Request, artifact_id: str):
    return export_artifact_download(request, artifact_id)

@router.post("/api/v1/exports/{artifact_id}/expire")
def api_export_expire(request: Request, artifact_id: str):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        return expire_export_artifact(DB_PATH, EXPORT_DIR, artifact_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.") from exc

@router.post("/api/v1/exports/{artifact_id}/pin")
def api_export_pin(request: Request, artifact_id: str, pinned: bool = True):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        return set_export_artifact_pinned(DB_PATH, artifact_id, pinned=bool(pinned), actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "내보내기 산출물을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/exports/storage/cleanup")
def api_export_storage_cleanup(request: Request):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        return enforce_export_storage_budget(
            DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES,
            actor=_actor(request),
        )
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
