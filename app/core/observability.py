from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import json
import logging
import re
import threading
import time
from typing import Any

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.time)
    requests_total: Counter[tuple[str, str, int]] = field(default_factory=Counter)
    request_seconds_sum: Counter[tuple[str, str]] = field(default_factory=Counter)
    webhook_delivery_total: Counter[str] = field(default_factory=Counter)
    job_execution_total: Counter[tuple[str, str]] = field(default_factory=Counter)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def observe_request(self, method: str, route: str, status: int, seconds: float) -> None:
        method = str(method).upper()
        route = str(route or "unknown")
        with self._lock:
            self.requests_total[(method, route, int(status))] += 1
            self.request_seconds_sum[(method, route)] += float(seconds)

    def observe_webhook(self, outcome: str) -> None:
        with self._lock:
            self.webhook_delivery_total[str(outcome)] += 1

    def observe_job(self, job_type: str, outcome: str) -> None:
        with self._lock:
            self.job_execution_total[(str(job_type), str(outcome))] += 1

    def render_prometheus(
        self, *, finding_count: int = 0, pending_webhooks: int = 0, active_jobs: int = 0,
        cluster_instances: int = 0, scheduler_leader: int = 0, export_storage_bytes: int = 0,
        export_storage_quota_bytes: int = 0, export_storage_pinned: int = 0,
        export_storage_pressure: int = 0, database_bytes: int = 0,
        database_wal_bytes: int = 0, database_reclaimable_bytes: int = 0,
        database_fts_in_sync: int = 1, config_baseline_present: int = 0,
        config_drift_changes: int = 0, config_change_pending: int = 0,
        config_change_approved: int = 0, idempotency_records: int = 0,
        execution_receipts: int = 0, execution_dead_letters: int = 0,
        execution_receipts_archived: int = 0,
    ) -> str:
        lines = [
            "# HELP vulnflow_uptime_seconds Process uptime.",
            "# TYPE vulnflow_uptime_seconds gauge",
            f"vulnflow_uptime_seconds {max(0.0, time.time() - self.started_at):.3f}",
            "# HELP vulnflow_findings_total Findings currently stored.",
            "# TYPE vulnflow_findings_total gauge",
            f"vulnflow_findings_total {int(finding_count)}",
            "# HELP vulnflow_webhook_pending Pending webhook deliveries.",
            "# TYPE vulnflow_webhook_pending gauge",
            f"vulnflow_webhook_pending {int(pending_webhooks)}",
            "# HELP vulnflow_background_jobs_active Pending, retrying, or running background jobs.",
            "# TYPE vulnflow_background_jobs_active gauge",
            f"vulnflow_background_jobs_active {int(active_jobs)}",
            "# HELP vulnflow_cluster_instances_active Active application instances registered in the shared database.",
            "# TYPE vulnflow_cluster_instances_active gauge",
            f"vulnflow_cluster_instances_active {int(cluster_instances)}",
            "# HELP vulnflow_scheduler_leader Whether this instance currently owns the scheduler lease.",
            "# TYPE vulnflow_scheduler_leader gauge",
            f"vulnflow_scheduler_leader {int(bool(scheduler_leader))}",
            "# HELP vulnflow_export_storage_bytes Managed export artifact bytes.",
            "# TYPE vulnflow_export_storage_bytes gauge",
            f"vulnflow_export_storage_bytes {int(export_storage_bytes)}",
            "# HELP vulnflow_export_storage_quota_bytes Configured export artifact quota bytes.",
            "# TYPE vulnflow_export_storage_quota_bytes gauge",
            f"vulnflow_export_storage_quota_bytes {int(export_storage_quota_bytes)}",
            "# HELP vulnflow_export_storage_pinned Protected export artifacts.",
            "# TYPE vulnflow_export_storage_pinned gauge",
            f"vulnflow_export_storage_pinned {int(export_storage_pinned)}",
            "# HELP vulnflow_export_storage_pressure Export storage pressure state.",
            "# TYPE vulnflow_export_storage_pressure gauge",
            f"vulnflow_export_storage_pressure {int(bool(export_storage_pressure))}",
            "# HELP vulnflow_database_bytes Main SQLite database bytes.",
            "# TYPE vulnflow_database_bytes gauge",
            f"vulnflow_database_bytes {int(database_bytes)}",
            "# HELP vulnflow_database_wal_bytes SQLite WAL file bytes.",
            "# TYPE vulnflow_database_wal_bytes gauge",
            f"vulnflow_database_wal_bytes {int(database_wal_bytes)}",
            "# HELP vulnflow_database_reclaimable_bytes Bytes represented by freelist pages.",
            "# TYPE vulnflow_database_reclaimable_bytes gauge",
            f"vulnflow_database_reclaimable_bytes {int(database_reclaimable_bytes)}",
            "# HELP vulnflow_database_fts_in_sync Whether finding rows and FTS rows are synchronized.",
            "# TYPE vulnflow_database_fts_in_sync gauge",
            f"vulnflow_database_fts_in_sync {int(database_fts_in_sync)}",
            "# HELP vulnflow_config_baseline_present Whether an approved redacted configuration baseline exists.",
            "# TYPE vulnflow_config_baseline_present gauge",
            f"vulnflow_config_baseline_present {int(bool(config_baseline_present))}",
            "# HELP vulnflow_config_drift_changes Current redacted configuration paths differing from the active baseline.",
            "# TYPE vulnflow_config_drift_changes gauge",
            f"vulnflow_config_drift_changes {int(config_drift_changes)}",
            "# HELP vulnflow_config_change_pending Pending configuration change approval requests.",
            "# TYPE vulnflow_config_change_pending gauge",
            f"vulnflow_config_change_pending {int(config_change_pending)}",
            "# HELP vulnflow_config_change_approved Approved configuration changes awaiting baseline promotion.",
            "# TYPE vulnflow_config_change_approved gauge",
            f"vulnflow_config_change_approved {int(config_change_approved)}",
            "# HELP vulnflow_idempotency_records_active Durable idempotency records that have not expired.",
            "# TYPE vulnflow_idempotency_records_active gauge",
            f"vulnflow_idempotency_records_active {int(idempotency_records)}",
            "# HELP vulnflow_execution_receipts_total Redacted execution attempt receipts.",
            "# TYPE vulnflow_execution_receipts_total gauge",
            f"vulnflow_execution_receipts_total {int(execution_receipts)}",
            "# HELP vulnflow_execution_dead_letters Unreplayed terminal failed or cancelled receipts.",
            "# TYPE vulnflow_execution_dead_letters gauge",
            f"vulnflow_execution_dead_letters {int(execution_dead_letters)}",
            "# HELP vulnflow_execution_receipts_archived_total Detailed receipts sealed into retention archives.",
            "# TYPE vulnflow_execution_receipts_archived_total gauge",
            f"vulnflow_execution_receipts_archived_total {int(execution_receipts_archived)}",
            "# HELP vulnflow_http_requests_total HTTP requests by method, route, and status.",
            "# TYPE vulnflow_http_requests_total counter",
        ]
        with self._lock:
            for (method, route, status), value in sorted(self.requests_total.items()):
                lines.append(
                    f'vulnflow_http_requests_total{{method="{_label(method)}",route="{_label(route)}",status="{status}"}} {value}'
                )
            lines += [
                "# HELP vulnflow_http_request_duration_seconds_sum Total request duration by method and route.",
                "# TYPE vulnflow_http_request_duration_seconds_sum counter",
            ]
            for (method, route), value in sorted(self.request_seconds_sum.items()):
                lines.append(
                    f'vulnflow_http_request_duration_seconds_sum{{method="{_label(method)}",route="{_label(route)}"}} {value:.6f}'
                )
            lines += [
                "# HELP vulnflow_webhook_deliveries_total Webhook delivery outcomes.",
                "# TYPE vulnflow_webhook_deliveries_total counter",
            ]
            for outcome, value in sorted(self.webhook_delivery_total.items()):
                lines.append(f'vulnflow_webhook_deliveries_total{{outcome="{_label(outcome)}"}} {value}')
            lines += [
                "# HELP vulnflow_background_job_executions_total Background job executions by type and outcome.",
                "# TYPE vulnflow_background_job_executions_total counter",
            ]
            for (job_type, outcome), value in sorted(self.job_execution_total.items()):
                lines.append(
                    f'vulnflow_background_job_executions_total{{job_type="{_label(job_type)}",outcome="{_label(outcome)}"}} {value}'
                )
        return "\n".join(lines) + "\n"


def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def configure_json_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("vulnflow")
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for key in ("request_id", "method", "path", "status", "duration_ms", "actor", "role", "event_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
