from __future__ import annotations

"""Foundation application service exports."""

from app.service_registry.common import export_namespace
from app.core.auth import (
    authenticate_request,
    has_role,
    parse_api_tokens,
)
from app.core.observability import (
    Metrics,
    REQUEST_ID_RE,
    configure_json_logging,
)
from app.core.signing import (
    build_signing_config,
    collect_signing_key_usage,
)
from app.core.public_signing import build_ed25519_signing_config
from app.core.scoring import (
    ACTIVE_STATUSES,
    ALLOWED_STATUSES,
    as_bool,
    exception_state,
    is_overdue,
    load_policy,
    parse_policy_text,
    policy_digest,
    parse_date,
    prioritize_finding,
)
from app.core.database_schema import (
    CURRENT_APP_VERSION,
    CURRENT_SCHEMA_VERSION,
    get_schema_info,
    init_coordination_db,
    init_db,
)
from app.core.db import (
    ConcurrencyError,
    utc_now,
)
from app.services.accounts import (
    authenticate_session,
    authenticate_user_password,
    count_active_users,
    create_session,
    create_user,
    get_user,
    hash_password,
    list_users,
    normalize_username,
    prune_auth_records,
    revoke_session,
    revoke_user_sessions,
    set_user_active,
    set_user_password,
    unlock_user,
    validate_password,
    verify_password,
)
from app.services.projects import (
    accessible_projects,
    create_project,
    default_project,
    get_project,
    list_project_members,
    list_projects,
    normalize_project_name,
    project_selection,
    resolve_project,
    set_project_membership,
    set_project_status,
)
from app.services.project_runtime import (
    decorate_project_rows,
    execute_background_job_with_project_scope,
    inspect_project_integrity,
    latest_project_backup,
    project_recovery_inventory,
    project_recovery_mode,
)

SERVICE_NAMES = (
    'authenticate_request',
    'authenticate_session',
    'authenticate_user_password',
    'count_active_users',
    'create_session',
    'create_user',
    'get_user',
    'hash_password',
    'list_users',
    'normalize_username',
    'prune_auth_records',
    'revoke_session',
    'revoke_user_sessions',
    'set_user_active',
    'set_user_password',
    'unlock_user',
    'validate_password',
    'verify_password',
    'accessible_projects',
    'create_project',
    'default_project',
    'get_project',
    'list_project_members',
    'list_projects',
    'normalize_project_name',
    'project_selection',
    'resolve_project',
    'set_project_membership',
    'set_project_status',
    'decorate_project_rows',
    'execute_background_job_with_project_scope',
    'inspect_project_integrity',
    'latest_project_backup',
    'project_recovery_inventory',
    'project_recovery_mode',
    'has_role',
    'parse_api_tokens',
    'Metrics',
    'REQUEST_ID_RE',
    'configure_json_logging',
    'build_signing_config',
    'collect_signing_key_usage',
    'build_ed25519_signing_config',
    'ACTIVE_STATUSES',
    'ALLOWED_STATUSES',
    'as_bool',
    'exception_state',
    'is_overdue',
    'load_policy',
    'parse_policy_text',
    'policy_digest',
    'parse_date',
    'prioritize_finding',
    'CURRENT_APP_VERSION',
    'CURRENT_SCHEMA_VERSION',
    'get_schema_info',
    'init_coordination_db',
    'init_db',
    'ConcurrencyError',
    'utc_now',
)
SERVICE_EXPORTS = export_namespace(globals(), SERVICE_NAMES)

__all__ = ["SERVICE_EXPORTS", "SERVICE_NAMES"]
