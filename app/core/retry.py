from __future__ import annotations

"""Shared retry and terminal-failure decisions for durable operations.

The policy is deliberately deterministic: the same operation key and attempt
number produce the same bounded jitter.  Raw payloads, URLs, tokens, and
idempotency keys are never included in diagnostic snapshots.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import sqlite3
from typing import Any


class RetryableOperationError(RuntimeError):
    """Explicitly mark an operation failure as safe to retry."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class PermanentOperationError(RuntimeError):
    """Explicitly mark an operation failure as terminal."""


@dataclass(frozen=True, slots=True)
class RetryDecision:
    status: str
    retryable: bool
    delay_seconds: int
    reason: str


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int
    base_delay_seconds: int
    max_delay_seconds: int
    multiplier: float = 2.0
    jitter_ratio: float = 0.1

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_attempts", max(1, int(self.max_attempts)))
        object.__setattr__(self, "base_delay_seconds", max(0, int(self.base_delay_seconds)))
        object.__setattr__(self, "max_delay_seconds", max(0, int(self.max_delay_seconds)))
        object.__setattr__(self, "multiplier", max(1.0, float(self.multiplier)))
        object.__setattr__(self, "jitter_ratio", min(0.5, max(0.0, float(self.jitter_ratio))))

    def delay_for(
        self,
        attempt: int,
        *,
        operation_key: str = "",
        retry_after_seconds: float | None = None,
    ) -> int:
        attempt_index = max(0, int(attempt) - 1)
        calculated = float(self.base_delay_seconds) * (self.multiplier ** attempt_index)
        bounded = min(float(self.max_delay_seconds), calculated)
        if retry_after_seconds is not None:
            bounded = max(bounded, min(float(self.max_delay_seconds), max(0.0, float(retry_after_seconds))))
        if bounded <= 0 or self.jitter_ratio <= 0:
            return max(0, int(round(bounded)))
        seed = hashlib.sha256(f"{operation_key}:{attempt_index}".encode("utf-8")).digest()
        unit = int.from_bytes(seed[:8], "big") / float(2**64 - 1)
        factor = 1.0 + ((unit * 2.0 - 1.0) * self.jitter_ratio)
        return max(0, min(self.max_delay_seconds, int(round(bounded * factor))))

    def decide(
        self,
        *,
        attempts: int,
        retryable: bool,
        operation_key: str = "",
        retry_after_seconds: float | None = None,
        cancelled: bool = False,
    ) -> RetryDecision:
        attempts = max(0, int(attempts))
        if cancelled:
            return RetryDecision("CANCELLED", False, 0, "cancel_requested")
        if not retryable:
            return RetryDecision("FAILED", False, 0, "permanent_failure")
        if attempts >= self.max_attempts:
            return RetryDecision("FAILED", False, 0, "attempt_limit_reached")
        return RetryDecision(
            "RETRY",
            True,
            self.delay_for(
                attempts,
                operation_key=operation_key,
                retry_after_seconds=retry_after_seconds,
            ),
            "transient_failure",
        )

    def structural_snapshot(self) -> dict[str, Any]:
        return {
            "max_attempts": self.max_attempts,
            "base_delay_seconds": self.base_delay_seconds,
            "max_delay_seconds": self.max_delay_seconds,
            "multiplier": self.multiplier,
            "jitter_ratio": self.jitter_ratio,
        }


def retryable_http_status(status_code: int | None) -> bool:
    if status_code is None:
        return True
    status = int(status_code)
    return status in {408, 425, 429} or 500 <= status <= 599


def parse_retry_after(value: str | None, *, now: datetime | None = None, cap_seconds: int = 3600) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    cap = max(0, int(cap_seconds))
    try:
        return min(cap, max(0, int(float(text))))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        reference = now or datetime.now(timezone.utc)
        return min(cap, max(0, int((parsed - reference).total_seconds())))
    except (TypeError, ValueError, OverflowError):
        return None


def classify_operation_exception(exc: BaseException) -> tuple[bool, float | None, str]:
    if isinstance(exc, PermanentOperationError):
        return False, None, "explicit_permanent"
    if isinstance(exc, RetryableOperationError):
        return True, exc.retry_after_seconds, "explicit_retryable"
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        return False, None, "invalid_input"
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True, None, "transport_failure"
    if isinstance(exc, sqlite3.OperationalError):
        message = str(exc).lower()
        if any(token in message for token in ("locked", "busy", "schema has changed", "vtable constructor failed")):
            return True, None, "sqlite_transient"
    # Preserve prior behavior for unknown runtime failures: retry within the
    # durable operation's configured attempt limit.
    return True, None, "unclassified_runtime"
