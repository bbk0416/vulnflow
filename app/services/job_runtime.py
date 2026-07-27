from __future__ import annotations

"""Compatibility facade for the split background-job runtime.

Application code must import the owning modules directly. Historical imports
from ``app.services.job_runtime`` remain supported with identical function
objects.
"""

from app.services.job_dispatch import execute_background_job
from app.services.job_worker_runtime import job_worker_loop

__all__ = ["execute_background_job", "job_worker_loop"]
