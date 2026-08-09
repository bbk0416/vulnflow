from __future__ import annotations

"""Per-project startup initialization after isolated integrity verification."""

from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

from app.core.context import ApplicationContext
from app.core.project_scope import ProjectSelection, project_scope
from app.services.database_identity import PROJECT_DATABASE_ROLE, set_database_identity
from app.services.project_runtime import (
    application_project_selections,
    inspect_project_integrity,
    mark_project_runtime_failure,
    project_identifier,
    project_recovery_mode,
)


def _service(context: ApplicationContext, name: str) -> Any:
    assert context.services is not None
    return context.services.require(name)



def _prepare_project_stores(
    context: ApplicationContext, *, signing_keys: dict[str, str]
) -> list[ProjectSelection | None]:
    """Migrate and verify each active project without aborting healthy peers."""
    selections = application_project_selections(context)
    context.set("PROJECT_RECOVERY_MODES", {})
    context.set("RECOVERY_MODE", {})
    for selection in selections:
        project_id = project_identifier(selection)
        scope = project_scope(selection) if isinstance(selection, ProjectSelection) else nullcontext()
        try:
            with scope:
                _service(context, "init_db")(context.get("DB_PATH"))
                set_database_identity(
                    context.get("DB_PATH"),
                    database_role=PROJECT_DATABASE_ROLE,
                    project_id=project_id,
                    project_name=(selection.name if isinstance(selection, ProjectSelection) else "기본 프로젝트"),
                )
            inspect_project_integrity(context, selection, signing_keys=signing_keys)
        except Exception as exc:
            context.logger.exception(
                "project database migration or integrity preparation failed",
                extra={"project_id": project_id},
            )
            mark_project_runtime_failure(context, selection, exc)
    return selections


def initialize_project_stores(
    context: ApplicationContext,
    *,
    signing: Any,
    ensure_policy_registry: Callable[[ApplicationContext], Any],
    load_sample_rows: Callable[[Path], list[dict[str, Any]]],
    rescore_all: Callable[..., Any],
) -> dict[str, Any]:
    """Inspect every project and initialize only stores that passed integrity checks."""
    selections = _prepare_project_stores(context, signing_keys=signing.keys)
    healthy: list[str] = []
    # Browser accounts and sessions live only in the control database.  Their
    # retention must never follow the active project path.
    _service(context, "prune_auth_records")(context.get("CONTROL_DB_PATH"))

    for selection in selections:
        project_id = project_identifier(selection)
        if project_recovery_mode(context, project_id).get("active"):
            continue
        scope = project_scope(selection) if isinstance(selection, ProjectSelection) else nullcontext()
        try:
            with scope:
                Path(context.get("EVIDENCE_DIR")).mkdir(parents=True, exist_ok=True)
                Path(context.get("EXPORT_DIR")).mkdir(parents=True, exist_ok=True)
                Path(context.get("RECOVERY_DIR")).mkdir(parents=True, exist_ok=True)
                _service(context, "reconcile_export_artifacts")(
                    context.get("DB_PATH"), context.get("EXPORT_DIR"), actor="system-startup"
                )
                ensure_policy_registry(context)
                sample_path = Path(context.get("SAMPLE_PATH"))
                if (
                    bool(context.get("DEMO_MODE", False))
                    and project_id == "default"
                    and _service(context, "count_findings")(context.get("DB_PATH")) == 0
                    and sample_path.exists()
                ):
                    _service(context, "upsert_findings")(
                        context.get("DB_PATH"),
                        load_sample_rows(sample_path),
                        actor="system-seed",
                    )
                rescore_all(audit=False, context=context)
                audit_key_id, audit_key = signing.active("audit")
                if audit_key:
                    current = _service(context, "verify_audit_integrity")(
                        context.get("DB_PATH"), signing_keys=signing.keys
                    )
                    checkpoints = current.get("checkpoints") or []
                    latest = checkpoints[-1] if checkpoints else {}
                    if (
                        not checkpoints
                        or int(latest.get("chain_seq") or -1) != int(current.get("last_seq") or 0)
                        or str(latest.get("key_id") or "") != str(audit_key_id or "")
                    ):
                        _service(context, "create_audit_checkpoint")(
                            context.get("DB_PATH"),
                            signing_key=audit_key,
                            signing_key_id=audit_key_id,
                            actor="system-startup",
                        )
            healthy.append(project_id)
        except Exception as exc:
            context.logger.exception(
                "project startup initialization failed",
                extra={"project_id": project_id},
            )
            mark_project_runtime_failure(context, selection, exc)

    modes = dict(context.get("PROJECT_RECOVERY_MODES", {}) or {})
    degraded = [item for item in modes.values() if item.get("active")]
    return {
        "project_count": len(modes),
        "healthy_count": len(healthy),
        "degraded_count": len(degraded),
        "healthy_project_ids": healthy,
        "modes": modes,
    }
