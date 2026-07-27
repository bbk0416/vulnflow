from __future__ import annotations

"""Compatibility facade for background-job persistence APIs.

New application code should import :mod:`app.repositories.job_records` or
:mod:`app.repositories.job_execution` according to ownership.
"""

from app.repositories.job_records import (
    JOB_TYPES, _job_row, count_active_background_jobs, create_background_job,
    get_background_job, list_background_jobs, purge_background_jobs,
    request_background_job_cancel, retry_background_job,
)
from app.repositories.job_execution import (
    claim_background_job, complete_background_job, fail_background_job,
    heartbeat_background_job,
)

__all__ = [
    "JOB_TYPES", "create_background_job", "get_background_job",
    "list_background_jobs", "count_active_background_jobs",
    "claim_background_job", "heartbeat_background_job",
    "complete_background_job", "fail_background_job",
    "request_background_job_cancel", "retry_background_job",
    "purge_background_jobs",
]
