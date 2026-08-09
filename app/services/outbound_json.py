from __future__ import annotations

"""Bounded JSON requests over the pinned outbound HTTP transport."""

from dataclasses import dataclass
import time
from typing import Any, Callable, Iterable, Mapping

from app.services.outbound_http import (
    OutboundError,
    OutboundPolicyError,
    OutboundResponse,
    OutboundResponseTooLarge,
    request_outbound,
)


class OutboundJsonError(OutboundError):
    """The remote service returned an unusable JSON response."""


class OutboundHTTPStatusError(OutboundJsonError):
    """The remote service returned an unexpected HTTP status."""

    def __init__(self, status_code: int):
        self.status_code = int(status_code)
        super().__init__(f"outbound service returned HTTP {self.status_code}")


@dataclass(frozen=True, slots=True)
class OutboundJsonResult:
    payload: dict[str, Any]
    attempts: int
    status_code: int
    headers: Mapping[str, str]


def _retry_delay(response: OutboundResponse | None, attempt: int) -> float:
    raw = str((response.headers.get("Retry-After") if response else "") or "").strip()
    if raw:
        try:
            return min(5.0, max(0.1, float(raw)))
        except ValueError:
            pass
    return min(0.25 * (2 ** max(0, attempt - 1)), 2.0)


def request_json_with_retries(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    timeout_seconds: int | float = 10,
    retries: int = 3,
    max_response_bytes: int = 1024 * 1024,
    allow_private_networks: bool = False,
    host_allowlist: str | Iterable[str] | None = None,
    accepted_statuses: Iterable[int] = (200,),
    retry_statuses: Iterable[int] = (429, 500, 502, 503, 504),
    sleep: Callable[[float], None] = time.sleep,
) -> OutboundJsonResult:
    """Return one JSON object without redirects, proxy inheritance, or DNS drift.

    Policy failures and oversized responses fail immediately. Transient transport
    failures and explicitly retryable HTTP statuses use a bounded backoff.
    """

    maximum_attempts = max(1, int(retries))
    accepted = {int(value) for value in accepted_statuses}
    retryable = {int(value) for value in retry_statuses}
    last_error: Exception | None = None

    for attempt in range(1, maximum_attempts + 1):
        response: OutboundResponse | None = None
        try:
            response = request_outbound(
                method,
                url,
                headers=headers,
                json_body=json_body,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks,
                host_allowlist=host_allowlist,
            )
            if 300 <= response.status_code < 400:
                raise OutboundHTTPStatusError(response.status_code)
            if response.status_code not in accepted:
                error = OutboundHTTPStatusError(response.status_code)
                if response.status_code in retryable and attempt < maximum_attempts:
                    last_error = error
                    sleep(_retry_delay(response, attempt))
                    continue
                raise error
            try:
                payload = response.json()
            except (UnicodeDecodeError, ValueError) as exc:
                raise OutboundJsonError("outbound service returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise OutboundJsonError("outbound service JSON must be an object")
            return OutboundJsonResult(
                payload=payload,
                attempts=attempt,
                status_code=response.status_code,
                headers=response.headers,
            )
        except (OutboundPolicyError, OutboundResponseTooLarge, OutboundHTTPStatusError, OutboundJsonError):
            raise
        except OutboundError as exc:
            last_error = exc
            if attempt >= maximum_attempts:
                break
            sleep(_retry_delay(response, attempt))

    if isinstance(last_error, OutboundError):
        raise last_error
    raise OutboundJsonError("outbound JSON request failed")
