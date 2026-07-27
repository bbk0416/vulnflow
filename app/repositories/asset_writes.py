from __future__ import annotations

"""Compatibility facade for asset write repositories.

New application code should import the owning repository directly. Existing
imports from :mod:`app.repositories.asset_writes` remain supported.
"""

from app.repositories.asset_identity_writes import (
    add_asset_identifier,
    get_asset_identity_candidate,
    list_asset_identifiers,
    list_asset_identity_candidates,
    reject_asset_identity_candidate,
)
from app.repositories.asset_inventory import (
    ASSET_STATUSES,
    _resolve_inventory_asset_ref_conn,
    apply_asset_inventory,
    extract_inventory_identifiers,
)
from app.repositories.asset_merge import (
    ASSET_MERGE_REQUEST_STATUSES,
    _asset_merge_impact_conn,
    _asset_merge_impact_digest,
    _decode_asset_merge_request,
    _merge_assets_conn,
    _persist_canonical_aggregate_conn,
    _preflight_asset_merge_request_conn,
    analyze_asset_merge,
    approve_asset_merge_request,
    create_asset_merge_request,
    get_asset_merge_request,
    list_asset_merge_history,
    list_asset_merge_requests,
    merge_assets,
    preflight_asset_merge_request,
    reject_asset_merge_request,
)
from app.repositories.asset_merge_rollback import (
    ASSET_MERGE_ROLLBACK_REQUEST_STATUSES,
    _asset_merge_rollback_impact_conn,
    _decode_asset_merge_rollback_journal,
    _decode_asset_merge_rollback_request,
    _preflight_asset_merge_rollback_request_conn,
    analyze_asset_merge_rollback,
    approve_asset_merge_rollback_request,
    create_asset_merge_rollback_request,
    get_asset_merge_rollback_request,
    list_asset_merge_rollback_requests,
    reject_asset_merge_rollback_request,
)

__all__ = [
    "ASSET_STATUSES",
    "ASSET_MERGE_REQUEST_STATUSES",
    "ASSET_MERGE_ROLLBACK_REQUEST_STATUSES",
    "extract_inventory_identifiers",
    "_resolve_inventory_asset_ref_conn",
    "list_asset_identifiers",
    "get_asset_identity_candidate",
    "list_asset_identity_candidates",
    "list_asset_merge_history",
    "add_asset_identifier",
    "reject_asset_identity_candidate",
    "_persist_canonical_aggregate_conn",
    "_asset_merge_impact_digest",
    "_asset_merge_impact_conn",
    "analyze_asset_merge",
    "_decode_asset_merge_request",
    "get_asset_merge_request",
    "list_asset_merge_requests",
    "create_asset_merge_request",
    "reject_asset_merge_request",
    "_preflight_asset_merge_request_conn",
    "preflight_asset_merge_request",
    "approve_asset_merge_request",
    "_merge_assets_conn",
    "merge_assets",
    "_decode_asset_merge_rollback_journal",
    "_decode_asset_merge_rollback_request",
    "get_asset_merge_rollback_request",
    "list_asset_merge_rollback_requests",
    "_asset_merge_rollback_impact_conn",
    "analyze_asset_merge_rollback",
    "create_asset_merge_rollback_request",
    "reject_asset_merge_rollback_request",
    "_preflight_asset_merge_rollback_request_conn",
    "approve_asset_merge_rollback_request",
    "apply_asset_inventory",
]
