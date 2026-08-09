from __future__ import annotations

"""Project-aware integrity state and operational storage helpers.

The control database owns the project registry, while every active project has
an independently verified operational database and storage tree.  Integrity
failures are recorded per project so one damaged customer store does not force
all healthy projects into read-only mode.
"""

from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.core.context import ApplicationContext
from app.core.project_scope import (
    ProjectScopedPath,
    ProjectSelection,
    active_project,
    project_scope,
)
from app.services.projects import list_projects, project_selection
from app.services.recovery_mode import build_recovery_mode, failed_integrity_report


def _service(context: ApplicationContext, name: str) -> Any:
    assert context.services is not None
    return context.services.require(name)


def _checked_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def application_project_selections(
    context: ApplicationContext,
) -> list[ProjectSelection | None]:
    """Return every active application project, preserving legacy single-DB use."""
    current_db = context.get("DB_PATH")
    if not isinstance(current_db, ProjectScopedPath):
        def compatibility_path(name: str, fallback: Path) -> Path:
            value = context.get(name, fallback)
            return value.fallback if isinstance(value, ProjectScopedPath) else Path(value)

        database = Path(current_db)
        root = database.parent
        return [
            ProjectSelection(
                project_id="default",
                name="기본 프로젝트",
                slug="default",
                database=database,
                evidence=compatibility_path("EVIDENCE_DIR", root / "evidence"),
                exports=compatibility_path("EXPORT_DIR", root / "exports"),
                import_previews=compatibility_path("IMPORT_PREVIEW_DIR", root / "import-previews"),
                recovery=compatibility_path("RECOVERY_DIR", root / "backups" / "recovery"),
                is_default=True,
            )
        ]
    control_db = context.get("CONTROL_DB_PATH")
    selections: list[ProjectSelection | None] = []
    for row in list_projects(control_db, admin=True):
        try:
            selections.append(
                project_selection(
                    control_db,
                    str(row["project_id"]),
                    projects_dir=context.get("PROJECTS_DIR"),
                    default_database_path=context.get("DEFAULT_PROJECT_DB_PATH"),
                    default_evidence_dir=context.get("DEFAULT_EVIDENCE_DIR"),
                    default_export_dir=context.get("DEFAULT_EXPORT_DIR"),
                    default_import_preview_dir=context.get("DEFAULT_IMPORT_PREVIEW_DIR"),
                    default_recovery_dir=context.get("DEFAULT_RECOVERY_DIR"),
                )
            )
        except (KeyError, OSError, RuntimeError):
            context.logger.exception(
                "project store could not be resolved",
                extra={"project_id": row.get("project_id")},
            )
    if selections:
        return selections
    # Compatibility contexts may replace the historical module-level DB_PATH
    # after application assembly and therefore have no usable control-registry
    # row during startup.  Keep fail-closed path resolution by creating an
    # explicit default selection instead of falling back outside project_scope.
    if isinstance(current_db, ProjectScopedPath):
        return [
            ProjectSelection(
                project_id="default",
                name="기본 프로젝트",
                slug="default",
                database=Path(context.get("DEFAULT_PROJECT_DB_PATH")),
                evidence=Path(context.get("DEFAULT_EVIDENCE_DIR")),
                exports=Path(context.get("DEFAULT_EXPORT_DIR")),
                import_previews=Path(context.get("DEFAULT_IMPORT_PREVIEW_DIR")),
                recovery=Path(context.get("DEFAULT_RECOVERY_DIR")),
                is_default=True,
            )
        ]
    return [None]



def execute_background_job_with_project_scope(
    context: ApplicationContext,
    job: dict[str, Any],
    *,
    worker_id: str,
    executor: Any,
) -> dict[str, Any]:
    """Run compatibility single-DB jobs inside an explicit default scope."""
    current_db = context.get("DB_PATH")
    if active_project() is not None or isinstance(current_db, ProjectScopedPath):
        return executor(context, job, worker_id=worker_id)
    selection = application_project_selections(context)[0]
    assert selection is not None
    with project_scope(selection):
        return executor(context, job, worker_id=worker_id)

def project_identifier(selection: ProjectSelection | None) -> str:
    return selection.project_id if selection is not None else "default"


def project_display_name(selection: ProjectSelection | None) -> str:
    return selection.name if selection is not None else "기본 프로젝트"


def project_recovery_mode(
    context: ApplicationContext,
    project_id: str | None = None,
) -> dict[str, Any]:
    selection = active_project()
    resolved = str(project_id or (selection.project_id if selection else "default"))
    modes = dict(context.get("PROJECT_RECOVERY_MODES", {}) or {})
    if resolved in modes:
        return dict(modes[resolved])
    if resolved == "default":
        return dict(context.get("RECOVERY_MODE", {}) or {})
    return {
        "active": False,
        "read_only": False,
        "reasons": [],
        "project_id": resolved,
        "checked_at": "",
        "status": "UNCHECKED",
    }


def project_is_read_only(
    context: ApplicationContext,
    selection: ProjectSelection | None = None,
) -> bool:
    return bool(project_recovery_mode(context, project_identifier(selection)).get("active"))


def _record_mode(
    context: ApplicationContext,
    project_id: str,
    mode: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(mode)
    modes = dict(context.get("PROJECT_RECOVERY_MODES", {}) or {})
    modes[project_id] = payload
    context.set("PROJECT_RECOVERY_MODES", modes)
    if project_id == "default":
        context.set("RECOVERY_MODE", payload)
    return payload


def inspect_project_integrity(
    context: ApplicationContext,
    selection: ProjectSelection | None,
    *,
    signing_keys: Mapping[str, str] | None = None,
    update_context: bool = True,
) -> dict[str, Any]:
    """Verify one project and return its isolated recovery-mode state."""
    project_id = project_identifier(selection)
    name = project_display_name(selection)
    scope = project_scope(selection) if selection is not None else nullcontext()
    with scope:
        try:
            evidence = _service(context, "verify_evidence_store")(
                context.get("DB_PATH"), Path(context.get("EVIDENCE_DIR"))
            )
        except Exception as exc:
            context.logger.exception(
                "project evidence integrity verification failed",
                extra={"project_id": project_id},
            )
            evidence = failed_integrity_report("evidence", exc)
        try:
            audit = _service(context, "verify_audit_integrity")(
                context.get("DB_PATH"), signing_keys=dict(signing_keys or {})
            )
        except Exception as exc:
            context.logger.exception(
                "project audit integrity verification failed",
                extra={"project_id": project_id},
            )
            audit = failed_integrity_report("audit", exc)
    mode = build_recovery_mode(
        evidence_integrity=evidence,
        audit_integrity=audit,
    )
    mode.update(
        {
            "project_id": project_id,
            "project_name": name,
            "checked_at": _checked_at(),
            "status": "READ_ONLY" if mode["active"] else "HEALTHY",
        }
    )
    if update_context:
        return _record_mode(context, project_id, mode)
    return mode


def inspect_all_project_integrity(
    context: ApplicationContext,
    *,
    signing_keys: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    modes: dict[str, dict[str, Any]] = {}
    selections = application_project_selections(context)
    for selection in selections:
        mode = inspect_project_integrity(
            context,
            selection,
            signing_keys=signing_keys,
            update_context=False,
        )
        modes[project_identifier(selection)] = mode
    context.set("PROJECT_RECOVERY_MODES", modes)
    context.set("RECOVERY_MODE", dict(modes.get("default", {}) or {}))
    degraded = [item for item in modes.values() if item.get("active")]
    return {
        "project_count": len(modes),
        "healthy_count": len(modes) - len(degraded),
        "degraded_count": len(degraded),
        "modes": modes,
        "selections": selections,
    }


def mark_project_runtime_failure(
    context: ApplicationContext,
    selection: ProjectSelection | None,
    exc: BaseException,
) -> dict[str, Any]:
    project_id = project_identifier(selection)
    mode = project_recovery_mode(context, project_id)
    reasons = list(mode.get("reasons") or [])
    reasons.append(f"시작 초기화: {type(exc).__name__}")
    mode.update(
        {
            "active": True,
            "read_only": True,
            "reasons": reasons,
            "status": "READ_ONLY",
            "runtime_error_type": type(exc).__name__,
            "checked_at": _checked_at(),
        }
    )
    return _record_mode(context, project_id, mode)


def latest_project_backup(selection: ProjectSelection | None, context: ApplicationContext) -> dict[str, Any] | None:
    scope = project_scope(selection) if selection is not None else nullcontext()
    with scope:
        root = Path(context.get("RECOVERY_DIR"))
        bundles = sorted(
            (path for path in root.glob("vulnflow_recovery_*.zip") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    if not bundles:
        return None
    latest = bundles[0]
    stat = latest.stat()
    return {
        "filename": latest.name,
        "size_bytes": int(stat.st_size),
        "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "bundle_count": len(bundles),
    }


def project_recovery_inventory(
    selection: ProjectSelection | None,
    context: ApplicationContext,
    *,
    limit: int = 20,
) -> dict[str, Any]:
    """Return local, external, and drill recovery state for one project."""
    project_id = project_identifier(selection)
    scope = project_scope(selection) if selection is not None else nullcontext()
    with scope:
        recovery_root = Path(context.get("RECOVERY_DIR"))
        local = _service(context, "list_local_recovery_bundles")(
            recovery_root, limit=limit
        )
        drills = _service(context, "list_recovery_drills")(
            recovery_root / "drills", limit=limit
        )
    external = _service(context, "list_external_recovery_bundles")(
        context.get("EXTERNAL_BACKUP_DIR"),
        project_id=project_id,
        limit=limit,
    )
    return {
        "local": local,
        "external": external,
        "drills": drills,
        "latest_local": local[0] if local else None,
        "latest_external": external[0] if external else None,
        "latest_drill": drills[0] if drills else None,
        "external_configured": context.get("EXTERNAL_BACKUP_DIR") is not None,
    }


def decorate_project_rows(
    context: ApplicationContext,
    rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    selections = {
        project_identifier(selection): selection
        for selection in application_project_selections(context)
    }
    output: list[dict[str, Any]] = []
    for source in rows:
        row = dict(source)
        project_id = str(row.get("project_id") or "")
        selection = selections.get(project_id)
        mode = project_recovery_mode(context, project_id)
        row["integrity"] = {
            "status": str(mode.get("status") or "UNCHECKED"),
            "active": bool(mode.get("active")),
            "checked_at": str(mode.get("checked_at") or ""),
            "reasons": list(mode.get("reasons") or []),
        }
        row["latest_backup"] = (
            latest_project_backup(selection, context)
            if selection is not None and str(row.get("status")) == "ACTIVE"
            else None
        )
        output.append(row)
    return output
