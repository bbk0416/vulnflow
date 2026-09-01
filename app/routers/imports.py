from __future__ import annotations
from app.ui_i18n import localized_template

"""Scanner-aware finding import preview and mapping routes."""

import csv
import io
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = (
    "upload_findings_preview",
    "upload_findings_recheck",
    "upload_findings_errors",
    "upload_findings_compatibility",
    "upload_findings_anonymize",
    "upload_findings_apply",
)

def _preview_mapping(form: Any, default: dict[str, str]) -> dict[str, str]:
    mapping = dict(default)
    for field in CANONICAL_IMPORT_FIELDS:
        name = str(field["name"])
        key = f"map__{name}"
        if key in form:
            mapping[name] = str(form.get(key) or "").strip()
    return mapping


def _preview_context(
    request: Request,
    *,
    token: str,
    metadata: dict[str, Any],
    evaluation: dict[str, Any],
    scanner_source: str,
    import_mode: str,
    notice: str = "",
) -> dict[str, Any]:
    preview_rows = []
    for row in evaluation["valid_rows"][:10]:
        preview_rows.append({
            "product": row.get("product", ""),
            "cve_id": row.get("cve_id", ""),
            "asset_name": row.get("asset_name", "") or row.get("ip_address", ""),
            "cvss": row.get("cvss", ""),
            "decision": row.get("decision", ""),
        })
    return {
        "token": token,
        "filename": metadata["filename"],
        "format_label": import_format_label(evaluation["detected_format"]),
        "detected_format": evaluation["detected_format"],
        "adapter": evaluation["adapter"],
        "headers": evaluation["headers"],
        "mapping": evaluation["mapping"],
        "mapping_fields": CANONICAL_IMPORT_FIELDS,
        "scanner_source": scanner_source,
        "import_mode": import_mode,
        "source_row_count": len(evaluation["rows"]) + len(evaluation.get("source_errors", [])),
        "mapped_row_count": evaluation["mapped_row_count"],
        "valid_count": len(evaluation["valid_rows"]),
        "error_count": len(evaluation["errors"]),
        "errors": evaluation["errors"][:30],
        "preview_rows": preview_rows,
        "metadata": evaluation.get("metadata", {}),
        "compatibility": build_scanner_compatibility_report(evaluation, filename=metadata["filename"]),
        "notice_message": notice,
    }


def _load_preview_for_actor(request: Request, token: str) -> tuple[dict[str, Any], bytes]:
    try:
        return load_preview_session(
            IMPORT_PREVIEW_DIR, token, actor=_actor(request), ttl_seconds=IMPORT_PREVIEW_TTL_SECONDS,
        )
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _validated_import_options(form: Any) -> tuple[str, str]:
    scanner_source = _bounded_text(form.get("scanner_source"), "scanner_source", 120) or "manual"
    import_mode = str(form.get("import_mode") or "incremental").strip().lower()
    if import_mode not in {"incremental", "snapshot"}:
        raise ValueError("가져오기 방식은 incremental 또는 snapshot이어야 합니다.")
    return scanner_source, import_mode


@router.post("/upload/findings/preview", response_class=HTMLResponse)
async def upload_findings_preview(
    request: Request,
    file: UploadFile = File(...),
    scanner_source: str = Form(""),
    import_mode: str = Form("incremental"),
    format_hint: str = Form("auto"),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    filename = file.filename or "upload"
    content = await file.read(MAX_IMPORT_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(400, "빈 파일은 가져올 수 없습니다.")
    if len(content) > MAX_IMPORT_UPLOAD_BYTES:
        raise HTTPException(413, f"가져오기 파일은 최대 {MAX_IMPORT_UPLOAD_BYTES // (1024 * 1024)}MB입니다.")
    try:
        parsed = parse_import_file(content, filename=filename, format_hint=format_hint)
        source = _bounded_text(scanner_source, "scanner_source", 120) or parsed["scanner_source_suggestion"]
        mode = str(import_mode or "incremental").strip().lower()
        if mode not in {"incremental", "snapshot"}:
            raise ValueError("가져오기 방식은 incremental 또는 snapshot이어야 합니다.")
        evaluation = _evaluate_finding_import(
            content, filename=filename, format_hint=format_hint, mapping=None,
            scanner_source=source, allow_empty=(mode == "snapshot"),
        )
        token = create_preview_session(
            IMPORT_PREVIEW_DIR, content=content, filename=filename, format_hint=format_hint,
            actor=_actor(request), ttl_seconds=IMPORT_PREVIEW_TTL_SECONDS,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    metadata = {"filename": Path(filename).name, "format_hint": format_hint}
    return templates.TemplateResponse(
        request=request,
        name=localized_template(request, "import_preview.html"),
        context=_preview_context(
            request, token=token, metadata=metadata, evaluation=evaluation,
            scanner_source=source, import_mode=mode,
        ),
    )


@router.post("/upload/findings/recheck", response_class=HTMLResponse)
async def upload_findings_recheck(request: Request):
    _require_role(request, "operator")
    form = await request.form()
    _verify_csrf(request, str(form.get("csrf_token") or ""))
    token = str(form.get("token") or "")
    metadata, content = _load_preview_for_actor(request, token)
    try:
        scanner_source, import_mode = _validated_import_options(form)
        initial = parse_import_file(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto")
        )
        mapping = _preview_mapping(form, initial["mapping"])
        evaluation = _evaluate_finding_import(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto"),
            mapping=mapping, scanner_source=scanner_source, allow_empty=(import_mode == "snapshot"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(
        request=request,
        name=localized_template(request, "import_preview.html"),
        context=_preview_context(
            request, token=token, metadata=metadata, evaluation=evaluation,
            scanner_source=scanner_source, import_mode=import_mode,
            notice="현재 열 매핑으로 다시 검사했습니다.",
        ),
    )


@router.post("/upload/findings/errors")
async def upload_findings_errors(request: Request):
    _require_role(request, "operator")
    form = await request.form()
    _verify_csrf(request, str(form.get("csrf_token") or ""))
    token = str(form.get("token") or "")
    metadata, content = _load_preview_for_actor(request, token)
    try:
        scanner_source, import_mode = _validated_import_options(form)
        initial = parse_import_file(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto")
        )
        mapping = _preview_mapping(form, initial["mapping"])
        evaluation = _evaluate_finding_import(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto"),
            mapping=mapping, scanner_source=scanner_source, allow_empty=(import_mode == "snapshot"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["row_number", "message", "raw"])
    writer.writeheader()
    for error in evaluation["errors"]:
        writer.writerow({
            "row_number": error.get("row_number", ""),
            "message": error.get("message", ""),
            "raw": str(error.get("raw", {})),
        })
    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulnflow-import-errors.csv"'},
    )


@router.post("/upload/findings/compatibility")
async def upload_findings_compatibility(request: Request):
    _require_role(request, "operator")
    form = await request.form()
    _verify_csrf(request, str(form.get("csrf_token") or ""))
    token = str(form.get("token") or "")
    metadata, content = _load_preview_for_actor(request, token)
    try:
        scanner_source, import_mode = _validated_import_options(form)
        initial = parse_import_file(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto")
        )
        mapping = _preview_mapping(form, initial["mapping"])
        evaluation = _evaluate_finding_import(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto"),
            mapping=mapping, scanner_source=scanner_source, allow_empty=(import_mode == "snapshot"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    report = build_scanner_compatibility_report(evaluation, filename=metadata["filename"])
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    return Response(
        content=payload,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulnflow-scanner-compatibility.json"'},
    )


@router.post("/upload/findings/anonymize")
async def upload_findings_anonymize(
    request: Request,
    file: UploadFile = File(...),
    profile: str = Form("compatibility"),
    format_hint: str = Form("auto"),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    filename = file.filename or "scanner-export"
    content = await file.read(MAX_IMPORT_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(400, "빈 파일은 익명화할 수 없습니다.")
    if len(content) > MAX_IMPORT_UPLOAD_BYTES:
        raise HTTPException(413, f"익명화 파일은 최대 {MAX_IMPORT_UPLOAD_BYTES // (1024 * 1024)}MB입니다.")
    try:
        bundle, _ = build_scanner_collection_bundle(
            content, filename=filename, format_hint=format_hint, profile=profile,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return Response(
        content=bundle,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="vulnflow-scanner-collection-bundle.zip"'},
    )


@router.post("/upload/findings/apply")
async def upload_findings_apply(request: Request):
    _require_role(request, "operator")
    form = await request.form()
    _verify_csrf(request, str(form.get("csrf_token") or ""))
    token = str(form.get("token") or "")
    metadata, content = _load_preview_for_actor(request, token)
    try:
        scanner_source, import_mode = _validated_import_options(form)
        initial = parse_import_file(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto")
        )
        mapping = _preview_mapping(form, initial["mapping"])
        evaluation = _evaluate_finding_import(
            content, filename=metadata["filename"], format_hint=metadata.get("format_hint", "auto"),
            mapping=mapping, scanner_source=scanner_source, allow_empty=(import_mode == "snapshot"),
        )
        skip_invalid = str(form.get("skip_invalid") or "").strip().lower() in {"1", "true", "on", "yes"}
        if evaluation["errors"] and not skip_invalid:
            return templates.TemplateResponse(
                request=request,
                name=localized_template(request, "import_preview.html"),
                status_code=400,
                context=_preview_context(
                    request, token=token, metadata=metadata, evaluation=evaluation,
                    scanner_source=scanner_source, import_mode=import_mode,
                    notice="오류가 남아 있습니다. 매핑을 수정하거나 유효한 행만 가져오기를 선택하세요.",
                ),
            )
        if evaluation["errors"] and import_mode == "snapshot":
            return templates.TemplateResponse(
                request=request,
                name=localized_template(request, "import_preview.html"),
                status_code=400,
                context=_preview_context(
                    request, token=token, metadata=metadata, evaluation=evaluation,
                    scanner_source=scanner_source, import_mode=import_mode,
                    notice="전체 결과 대조에서는 오류 행을 건너뛸 수 없습니다. 누락 판정을 막기 위해 모든 오류를 먼저 해결하세요.",
                ),
            )
        rows = evaluation["valid_rows"]
        if not rows:
            raise ValueError("반영할 수 있는 유효한 취약점이 없습니다.")
        result = apply_import_batch(
            DB_PATH, rows, scanner_source=scanner_source, filename=metadata["filename"],
            reconcile_missing=(import_mode == "snapshot"), actor=_actor(request),
            verification_absence_threshold=VERIFICATION_ABSENCE_SCANS,
        )
        result["skipped_invalid_count"] = len(evaluation["errors"])
        _queue_webhook("import.completed", result, _actor(request))
        delete_preview_session(IMPORT_PREVIEW_DIR, token)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    notice = "upload_partial" if evaluation["errors"] else "upload_ok"
    return RedirectResponse(url=f"/?notice={notice}", status_code=303)


