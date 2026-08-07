from __future__ import annotations

"""Workflow application service exports."""

from app.service_registry.common import export_namespace
from app.services.database_lifecycle import (
    backup_database,
    list_maintenance_runs,
    restore_database,
    validate_database_file,
)
from app.services.evidence import (
    get_evidence_artifact,
    list_evidence_artifacts,
    resolve_evidence_path,
    retire_evidence_artifact,
    store_verification_evidence,
    scan_evidence_artifact,
    waive_evidence_scan,
    evidence_download_allowed,
    verify_evidence_artifact,
    verify_evidence_store,
    list_evidence_custody_events,
    verify_evidence_custody_chain,
    transfer_evidence_custody,
    record_evidence_access,
)
from app.services.intel import (
    IntelligenceError,
    fetch_epss,
    fetch_kev_catalog,
)
from app.services.maintenance import (
    record_maintenance_failure,
    run_maintenance,
)
from app.services.database_maintenance import (
    database_health,
    list_database_maintenance_runs,
    run_database_maintenance,
)
from app.services.report import (
    generate_executive_html_report,
    generate_html_report,
    report_summary,
)
from app.services.finding_query import (
    finding_summary,
    list_scanner_sources,
    operational_counts,
    query_findings,
)
from app.services.scanner_compatibility import build_scanner_compatibility_report
from app.services.scanner_anonymization import build_scanner_collection_bundle
from app.services.finding_imports import (
    CANONICAL_IMPORT_FIELDS,
    create_preview_session,
    delete_preview_session,
    import_format_label,
    load_preview_session,
    map_import_rows,
    parse_import_file,
)
from app.services.exports import (
    create_findings_csv_export,
    enforce_export_storage_budget,
    expire_export_artifact,
    export_storage_status,
    get_export_artifact,
    list_export_artifacts,
    mark_export_artifact_corrupt,
    purge_expired_export_artifacts,
    reconcile_export_artifacts,
    record_export_download,
    resolve_export_artifact_path,
    set_export_artifact_pinned,
    stream_findings_csv,
    verify_export_artifact,
)
from app.services.pilot_readiness import build_pilot_readiness

SERVICE_NAMES = (
    'build_scanner_compatibility_report',
    'build_scanner_collection_bundle',
    'CANONICAL_IMPORT_FIELDS',
    'create_preview_session',
    'delete_preview_session',
    'import_format_label',
    'load_preview_session',
    'map_import_rows',
    'parse_import_file',
    'backup_database',
    'list_maintenance_runs',
    'restore_database',
    'validate_database_file',
    'get_evidence_artifact',
    'list_evidence_artifacts',
    'resolve_evidence_path',
    'retire_evidence_artifact',
    'store_verification_evidence',
    'scan_evidence_artifact',
    'waive_evidence_scan',
    'evidence_download_allowed',
    'verify_evidence_artifact',
    'verify_evidence_store',
    'list_evidence_custody_events',
    'verify_evidence_custody_chain',
    'transfer_evidence_custody',
    'record_evidence_access',
    'IntelligenceError',
    'fetch_epss',
    'fetch_kev_catalog',
    'record_maintenance_failure',
    'run_maintenance',
    'database_health',
    'list_database_maintenance_runs',
    'run_database_maintenance',
    'generate_executive_html_report',
    'generate_html_report',
    'report_summary',
    'build_pilot_readiness',
    'finding_summary',
    'list_scanner_sources',
    'operational_counts',
    'query_findings',
    'create_findings_csv_export',
    'enforce_export_storage_budget',
    'expire_export_artifact',
    'export_storage_status',
    'get_export_artifact',
    'list_export_artifacts',
    'mark_export_artifact_corrupt',
    'purge_expired_export_artifacts',
    'reconcile_export_artifacts',
    'record_export_download',
    'resolve_export_artifact_path',
    'set_export_artifact_pinned',
    'stream_findings_csv',
    'verify_export_artifact',
)
SERVICE_EXPORTS = export_namespace(globals(), SERVICE_NAMES)

__all__ = ["SERVICE_EXPORTS", "SERVICE_NAMES"]
