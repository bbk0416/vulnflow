from __future__ import annotations

"""Scanner compatibility facade preserving the public import surface."""

from app.services.scanner_compatibility_evaluation import evaluate_scanner_file
from app.services.scanner_compatibility_report import build_scanner_compatibility_report

__all__ = ["build_scanner_compatibility_report", "evaluate_scanner_file"]
