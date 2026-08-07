from __future__ import annotations

"""Per-request project data-path isolation.

VulnFlow keeps authentication and the project registry in the control database.
Each non-default project receives its own SQLite database and storage folders.
Existing repository signatures remain unchanged through path-like proxies that
resolve against a context-local :class:`ProjectSelection`.
"""

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterator, Literal

ProjectPathKind = Literal[
    "database", "evidence", "exports", "import_previews", "recovery"
]


@dataclass(frozen=True, slots=True)
class ProjectSelection:
    project_id: str
    name: str
    slug: str
    database: Path
    evidence: Path
    exports: Path
    import_previews: Path
    recovery: Path
    is_default: bool = False

    def path_for(self, kind: ProjectPathKind) -> Path:
        return Path(getattr(self, kind))


_ACTIVE_PROJECT: ContextVar[ProjectSelection | None] = ContextVar(
    "vulnflow_active_project", default=None
)


def active_project() -> ProjectSelection | None:
    return _ACTIVE_PROJECT.get()


def activate_project(selection: ProjectSelection) -> Token[ProjectSelection | None]:
    return _ACTIVE_PROJECT.set(selection)


def reset_project(token: Token[ProjectSelection | None]) -> None:
    _ACTIVE_PROJECT.reset(token)


@contextmanager
def project_scope(selection: ProjectSelection) -> Iterator[ProjectSelection]:
    token = activate_project(selection)
    try:
        yield selection
    finally:
        reset_project(token)


class ProjectScopedPath(os.PathLike[str]):
    """A path-like value that follows the active request project.

    Outside a project scope it resolves to the legacy/default location. This
    preserves CLI, migration, and existing single-project behavior.
    """

    __slots__ = ("kind", "fallback", "require_scope")

    def __init__(
        self, kind: ProjectPathKind, fallback: str | Path, *, require_scope: bool = False
    ) -> None:
        self.kind = kind
        self.fallback = Path(fallback)
        self.require_scope = bool(require_scope)

    def resolve_path(self) -> Path:
        selection = active_project()
        if selection is not None:
            return selection.path_for(self.kind)
        if self.require_scope:
            raise RuntimeError(
                f"프로젝트 범위 없이 {self.kind} 경로에 접근할 수 없습니다."
            )
        return self.fallback

    def __fspath__(self) -> str:
        return os.fspath(self.resolve_path())

    def __str__(self) -> str:
        return str(self.resolve_path())

    def __repr__(self) -> str:
        return f"ProjectScopedPath(kind={self.kind!r}, current={str(self)!r})"

    def __truediv__(self, key: object) -> Path:
        return self.resolve_path() / key  # type: ignore[arg-type]

    def __rtruediv__(self, key: object) -> Path:
        return Path(key) / self.resolve_path()  # type: ignore[arg-type]

    def __getattr__(self, name: str):
        return getattr(self.resolve_path(), name)


def configure_project_scoped_settings(context: object) -> None:
    """Install per-request project paths while keeping the control DB separate."""
    settings = getattr(context, "settings", None)
    namespace = getattr(context, "namespace", None)
    if settings is None or namespace is None:
        raise RuntimeError("application context is not initialized")
    current_db = settings.get("DB_PATH")
    if isinstance(current_db, ProjectScopedPath):
        return

    def configured_path(name: str, fallback: object | None = None) -> Path:
        value = settings.get(name, fallback)
        if isinstance(value, ProjectScopedPath):
            return value.fallback
        return Path(value)

    default_database = configured_path("DEFAULT_PROJECT_DB_PATH", current_db)
    control_database = configured_path("CONTROL_DB_PATH")
    if default_database.resolve() == control_database.resolve():
        raise RuntimeError("제어 DB와 기본 프로젝트 DB는 서로 다른 파일이어야 합니다.")
    evidence = configured_path("EVIDENCE_DIR")
    exports = configured_path("EXPORT_DIR")
    previews = configured_path("IMPORT_PREVIEW_DIR")
    recovery = configured_path("RECOVERY_DIR")
    data_dir = configured_path("DATA_DIR", control_database.parent)
    projects_dir = configured_path("PROJECTS_DIR", data_dir / "projects")
    overrides = {
        "CONTROL_DB_PATH": control_database,
        "DEFAULT_PROJECT_DB_PATH": default_database,
        "PROJECTS_DIR": projects_dir,
        "DEFAULT_EVIDENCE_DIR": evidence,
        "DEFAULT_EXPORT_DIR": exports,
        "DEFAULT_IMPORT_PREVIEW_DIR": previews,
        "DEFAULT_RECOVERY_DIR": recovery,
        "DB_PATH": ProjectScopedPath("database", default_database, require_scope=True),
        "EVIDENCE_DIR": ProjectScopedPath("evidence", evidence, require_scope=True),
        "EXPORT_DIR": ProjectScopedPath("exports", exports, require_scope=True),
        "IMPORT_PREVIEW_DIR": ProjectScopedPath("import_previews", previews, require_scope=True),
        "RECOVERY_DIR": ProjectScopedPath("recovery", recovery, require_scope=True),
    }
    context.settings = settings.with_overrides(overrides)
    namespace.update(overrides)
