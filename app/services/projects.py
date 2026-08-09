from __future__ import annotations

"""Project registry, memberships, and physically isolated project storage."""

from dataclasses import asdict
from pathlib import Path
import re
import shutil
import secrets
import unicodedata
from typing import Any, Callable

from app.core.auth import Principal
from app.core.db import utc_now
from app.core.project_scope import ProjectSelection
from app.core.transactions import read_connection, write_transaction
from app.services.database_identity import PROJECT_DATABASE_ROLE, set_database_identity

_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")


def normalize_project_name(name: str) -> str:
    value = unicodedata.normalize("NFKC", str(name or "")).strip()
    if len(value) < 2 or len(value) > 80:
        raise ValueError("프로젝트 이름은 2~80자로 입력하세요.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("프로젝트 이름에 제어 문자를 사용할 수 없습니다.")
    return value


def project_slug(name: str) -> str:
    text = unicodedata.normalize("NFKD", normalize_project_name(name)).lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:40]
    return text or "project"


def _project_id(slug: str) -> str:
    return f"{slug[:40]}-{secrets.token_hex(4)}"


def _row_selection(
    row: dict[str, Any],
    *,
    control_db_path: str | Path,
    projects_dir: str | Path,
    default_database_path: str | Path,
    default_evidence_dir: str | Path,
    default_export_dir: str | Path,
    default_import_preview_dir: str | Path,
    default_recovery_dir: str | Path,
) -> ProjectSelection:
    is_default = bool(int(row.get("is_default") or 0))
    if is_default:
        database = Path(default_database_path)
        evidence = Path(default_evidence_dir)
        exports = Path(default_export_dir)
        previews = Path(default_import_preview_dir)
        recovery = Path(default_recovery_dir)
    else:
        root = Path(projects_dir) / str(row["project_id"])
        database = root / "vulnflow.db"
        evidence = root / "evidence"
        exports = root / "exports"
        previews = root / "import-previews"
        recovery = root / "backups" / "recovery"
    return ProjectSelection(
        project_id=str(row["project_id"]),
        name=str(row["name"]),
        slug=str(row["slug"]),
        database=database,
        evidence=evidence,
        exports=exports,
        import_previews=previews,
        recovery=recovery,
        is_default=is_default,
    )


def list_projects(
    control_db_path: str | Path,
    *,
    username: str = "",
    include_inactive: bool = False,
    admin: bool = False,
) -> list[dict[str, Any]]:
    where = [] if include_inactive else ["p.status='ACTIVE'"]
    params: list[Any] = []
    join = ""
    if username and not admin:
        join = "JOIN project_memberships m ON m.project_id=p.project_id"
        where.append("m.username=?")
        params.append(str(username).strip().lower())
    sql = (
        "SELECT p.project_id,p.name,p.slug,p.status,p.is_default,p.created_by,p.created_at,p.updated_at,"
        "(SELECT COUNT(*) FROM project_memberships m2 WHERE m2.project_id=p.project_id) AS member_count "
        f"FROM projects p {join}"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY p.is_default DESC,p.name,p.project_id"
    with read_connection(control_db_path, operation="list_projects") as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def get_project(control_db_path: str | Path, project_id: str) -> dict[str, Any] | None:
    value = str(project_id or "").strip().lower()
    if not _PROJECT_ID_RE.fullmatch(value):
        return None
    with read_connection(control_db_path, operation="get_project") as conn:
        row = conn.execute(
            """SELECT project_id,name,slug,status,is_default,created_by,created_at,updated_at
                 FROM projects WHERE project_id=?""",
            (value,),
        ).fetchone()
    return dict(row) if row else None


def default_project(control_db_path: str | Path) -> dict[str, Any]:
    with read_connection(control_db_path, operation="default_project") as conn:
        row = conn.execute(
            """SELECT project_id,name,slug,status,is_default,created_by,created_at,updated_at
                 FROM projects WHERE is_default=1 LIMIT 1"""
        ).fetchone()
    if not row:
        raise RuntimeError("기본 프로젝트가 초기화되지 않았습니다.")
    return dict(row)


def project_selection(
    control_db_path: str | Path,
    project_id: str,
    *,
    projects_dir: str | Path,
    default_database_path: str | Path,
    default_evidence_dir: str | Path,
    default_export_dir: str | Path,
    default_import_preview_dir: str | Path,
    default_recovery_dir: str | Path,
) -> ProjectSelection:
    row = get_project(control_db_path, project_id)
    if not row or str(row.get("status")) != "ACTIVE":
        raise KeyError("활성 프로젝트를 찾을 수 없습니다.")
    return _row_selection(
        row,
        control_db_path=control_db_path,
        projects_dir=projects_dir,
        default_database_path=default_database_path,
        default_evidence_dir=default_evidence_dir,
        default_export_dir=default_export_dir,
        default_import_preview_dir=default_import_preview_dir,
        default_recovery_dir=default_recovery_dir,
    )


def accessible_projects(
    control_db_path: str | Path,
    principal: Principal,
) -> list[dict[str, Any]]:
    if principal.auth_method == "bearer":
        allowed = set(principal.project_ids)
        rows = list_projects(control_db_path, admin=True)
        if "*" in allowed:
            return rows
        if not allowed:
            return []
        return [row for row in rows if str(row["project_id"]) in allowed]
    if principal.auth_method == "local" or principal.role == "admin":
        return list_projects(control_db_path, admin=True)
    return list_projects(control_db_path, username=principal.username, admin=False)


def resolve_project(
    control_db_path: str | Path,
    principal: Principal,
    requested_project_id: str = "",
) -> dict[str, Any]:
    projects = accessible_projects(control_db_path, principal)
    if not projects:
        raise PermissionError("접근 가능한 프로젝트가 없습니다. 관리자에게 프로젝트 배정을 요청하세요.")
    requested = str(requested_project_id or "").strip().lower()
    if requested:
        for row in projects:
            if str(row["project_id"]) == requested:
                return row
        raise PermissionError("해당 프로젝트에 접근할 권한이 없습니다.")
    return next((row for row in projects if int(row.get("is_default") or 0)), projects[0])


def create_project(
    control_db_path: str | Path,
    *,
    name: str,
    actor: str,
    projects_dir: str | Path,
    default_database_path: str | Path,
    default_evidence_dir: str | Path,
    default_export_dir: str | Path,
    default_import_preview_dir: str | Path,
    default_recovery_dir: str | Path,
    init_db_fn: Callable[[str | Path], None],
) -> dict[str, Any]:
    normalized_name = normalize_project_name(name)
    slug = project_slug(normalized_name)
    now = utc_now()
    with write_transaction(control_db_path, operation="create_project") as conn:
        existing = conn.execute(
            "SELECT 1 FROM projects WHERE lower(name)=lower(?) OR slug=?",
            (normalized_name, slug),
        ).fetchone()
        if existing:
            slug = f"{slug}-{secrets.token_hex(2)}"
        project_id = _project_id(slug)
        conn.execute(
            """INSERT INTO projects(project_id,name,slug,status,is_default,created_by,created_at,updated_at)
               VALUES(?,?,?,'ACTIVE',0,?,?,?)""",
            (project_id, normalized_name, slug, actor, now, now),
        )
        actor_username = str(actor or "").strip().lower()
        if actor_username and not actor_username.startswith("api:") and actor_username != "local-user":
            if conn.execute("SELECT 1 FROM app_users WHERE username=?", (actor_username,)).fetchone():
                conn.execute(
                    """INSERT OR IGNORE INTO project_memberships(project_id,username,created_by,created_at)
                       VALUES(?,?,?,?)""",
                    (project_id, actor_username, actor, now),
                )
    row = get_project(control_db_path, project_id)
    assert row is not None
    selection = _row_selection(
        row,
        control_db_path=control_db_path,
        projects_dir=projects_dir,
        default_database_path=default_database_path,
        default_evidence_dir=default_evidence_dir,
        default_export_dir=default_export_dir,
        default_import_preview_dir=default_import_preview_dir,
        default_recovery_dir=default_recovery_dir,
    )
    try:
        selection.database.parent.mkdir(parents=True, exist_ok=True)
        for directory in (selection.evidence, selection.exports, selection.import_previews, selection.recovery):
            directory.mkdir(parents=True, exist_ok=True)
        init_db_fn(selection.database)
        set_database_identity(
            selection.database,
            database_role=PROJECT_DATABASE_ROLE,
            project_id=selection.project_id,
            project_name=selection.name,
        )
    except Exception:
        with write_transaction(control_db_path, operation="rollback_project_create") as conn:
            conn.execute("DELETE FROM project_memberships WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
        if not selection.is_default:
            shutil.rmtree(selection.database.parent, ignore_errors=True)
        raise
    result = dict(row)
    result.update({"database": str(selection.database)})
    return result


def set_project_status(
    control_db_path: str | Path,
    *,
    project_id: str,
    active: bool,
    actor: str,
) -> dict[str, Any]:
    row = get_project(control_db_path, project_id)
    if not row:
        raise KeyError("프로젝트를 찾을 수 없습니다.")
    if int(row.get("is_default") or 0) and not active:
        raise ValueError("기본 프로젝트는 비활성화할 수 없습니다.")
    now = utc_now()
    with write_transaction(control_db_path, operation="set_project_status") as conn:
        conn.execute(
            "UPDATE projects SET status=?,updated_at=? WHERE project_id=?",
            ("ACTIVE" if active else "INACTIVE", now, project_id),
        )
    updated = get_project(control_db_path, project_id)
    assert updated is not None
    return updated


def list_project_members(control_db_path: str | Path, project_id: str) -> list[dict[str, Any]]:
    with read_connection(control_db_path, operation="list_project_members") as conn:
        rows = conn.execute(
            """SELECT u.username,u.role,u.is_active,
                      CASE WHEN m.username IS NULL THEN 0 ELSE 1 END AS is_member
                 FROM app_users u
                 LEFT JOIN project_memberships m
                   ON m.username=u.username AND m.project_id=?
                ORDER BY CASE u.role WHEN 'admin' THEN 0 WHEN 'approver' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END,
                         u.username""",
            (project_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def set_project_membership(
    control_db_path: str | Path,
    *,
    project_id: str,
    username: str,
    member: bool,
    actor: str,
) -> None:
    project = get_project(control_db_path, project_id)
    if not project:
        raise KeyError("프로젝트를 찾을 수 없습니다.")
    normalized = str(username or "").strip().lower()
    now = utc_now()
    with write_transaction(control_db_path, operation="set_project_membership") as conn:
        user = conn.execute(
            "SELECT username,role,is_active FROM app_users WHERE username=?", (normalized,)
        ).fetchone()
        if not user:
            raise KeyError("사용자를 찾을 수 없습니다.")
        if str(user["role"]) == "admin":
            raise ValueError("관리자는 모든 활성 프로젝트에 접근하므로 별도 프로젝트 배정을 변경할 수 없습니다.")
        if member:
            conn.execute(
                """INSERT INTO project_memberships(project_id,username,created_by,created_at)
                   VALUES(?,?,?,?)
                   ON CONFLICT(project_id,username) DO NOTHING""",
                (project_id, normalized, actor, now),
            )
        else:
            if int(project.get("is_default") or 0) and str(user["role"]) == "admin":
                raise ValueError("관리자는 기본 프로젝트 접근 권한을 제거할 수 없습니다.")
            conn.execute(
                "DELETE FROM project_memberships WHERE project_id=? AND username=?",
                (project_id, normalized),
            )


def selection_as_public_dict(selection: ProjectSelection) -> dict[str, Any]:
    data = asdict(selection)
    for key in ("database", "evidence", "exports", "import_previews", "recovery"):
        data.pop(key, None)
    return data
