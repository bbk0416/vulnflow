from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from app.core.retry import parse_retry_after, retryable_http_status
from app.core.database_schema import CURRENT_APP_VERSION
from app.core.db import utc_now
from app.repositories.webhook_delivery import list_due_webhook_events, record_webhook_delivery
from app.repositories.webhook_queue import enqueue_webhook_events


@dataclass(frozen=True)
class WebhookEndpoint:
    name: str
    url: str
    secret: str
    events: frozenset[str]


class WebhookConfigError(ValueError):
    pass


def parse_webhook_endpoints(raw_json: str, *, allow_insecure_http: bool = False) -> dict[str, WebhookEndpoint]:
    text = str(raw_json or "").strip()
    if not text:
        return {}
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WebhookConfigError("VULNFLOW_WEBHOOKS_JSON이 올바른 JSON이 아닙니다.") from exc
    if not isinstance(payload, dict):
        raise WebhookConfigError("VULNFLOW_WEBHOOKS_JSON은 엔드포인트 이름을 키로 하는 객체여야 합니다.")
    endpoints: dict[str, WebhookEndpoint] = {}
    for raw_name, item in payload.items():
        name = str(raw_name or "").strip()
        if not name or not isinstance(item, dict):
            raise WebhookConfigError("각 웹훅에는 url, secret, events가 필요합니다.")
        url = str(item.get("url") or "").strip()
        secret = str(item.get("secret") or "")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise WebhookConfigError(f"{name}: http 또는 https URL이 필요합니다.")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"} and not allow_insecure_http:
            raise WebhookConfigError(f"{name}: 원격 웹훅은 HTTPS가 필요합니다.")
        if len(secret) < 16:
            raise WebhookConfigError(f"{name}: secret은 최소 16자여야 합니다.")
        raw_events = item.get("events", ["*"])
        if not isinstance(raw_events, list) or not raw_events:
            raise WebhookConfigError(f"{name}: events는 비어 있지 않은 배열이어야 합니다.")
        events = frozenset(str(event).strip() for event in raw_events if str(event).strip())
        endpoints[name] = WebhookEndpoint(name=name, url=url, secret=secret, events=events)
    return endpoints


def matching_endpoint_names(endpoints: dict[str, WebhookEndpoint], event_type: str) -> list[str]:
    return [name for name, endpoint in endpoints.items() if "*" in endpoint.events or event_type in endpoint.events]


def queue_event(
    db_path: str | Path,
    *,
    endpoints: dict[str, WebhookEndpoint],
    event_type: str,
    payload: dict[str, Any],
    actor: str,
    idempotency_key: str | None = None,
    idempotency_retention_days: int = 30,
) -> list[str]:
    names = matching_endpoint_names(endpoints, event_type)
    if not names:
        return []
    envelope = {
        "schema_version": "1.0",
        "event_type": event_type,
        "occurred_at": utc_now(),
        "actor": actor,
        "data": payload,
    }
    return enqueue_webhook_events(
        db_path,
        endpoint_names=names,
        event_type=event_type,
        payload=envelope,
        actor=actor,
        idempotency_key=idempotency_key,
        idempotency_request={
            "endpoint_names": sorted(names),
            "event_type": event_type,
            "actor": actor,
            "data": payload,
        } if idempotency_key else None,
        idempotency_retention_days=idempotency_retention_days,
    )


def _signature(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def deliver_due_events(
    db_path: str | Path,
    *,
    endpoints: dict[str, WebhookEndpoint],
    timeout_seconds: int = 10,
    max_attempts: int = 5,
    limit: int = 50,
) -> dict[str, int]:
    summary = {"delivered": 0, "retry": 0, "failed": 0, "skipped": 0}
    for event in list_due_webhook_events(db_path, limit=limit):
        endpoint = endpoints.get(str(event.get("endpoint_name") or ""))
        if endpoint is None:
            result = record_webhook_delivery(
                db_path,
                event_id=event["event_id"],
                delivered=False,
                response_status=None,
                error="configured endpoint not found",
                max_attempts=max_attempts,
                retryable=False,
                failure_kind="configuration",
            )
            summary["failed" if result.get("status") == "FAILED" else "retry"] += 1
            continue
        payload = event.get("payload") or {}
        payload["event_id"] = event["event_id"]
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"VulnFlow/{CURRENT_APP_VERSION} webhook",
            "X-VulnFlow-Event-ID": event["event_id"],
            "X-VulnFlow-Event-Type": event["event_type"],
            "X-VulnFlow-Signature": _signature(endpoint.secret, body),
        }
        try:
            response = requests.post(
                endpoint.url, data=body, headers=headers,
                timeout=max(1, int(timeout_seconds)), allow_redirects=False,
            )
        except requests.RequestException as exc:
            result = record_webhook_delivery(
                db_path,
                event_id=event["event_id"],
                delivered=False,
                response_status=getattr(getattr(exc, "response", None), "status_code", None),
                error=str(exc)[:1000],
                max_attempts=max_attempts,
                retryable=True,
                failure_kind="transport",
            )
            summary["failed" if result.get("status") == "FAILED" else "retry"] += 1
            continue

        status_code = int(response.status_code)
        if not 200 <= status_code < 300:
            retry_after = parse_retry_after(
                getattr(response, "headers", {}).get("Retry-After"), cap_seconds=3600
            )
            result = record_webhook_delivery(
                db_path,
                event_id=event["event_id"],
                delivered=False,
                response_status=status_code,
                error=f"unexpected webhook status: {status_code}",
                max_attempts=max_attempts,
                retryable=retryable_http_status(status_code),
                retry_after_seconds=retry_after,
                failure_kind="http_status",
            )
            summary["failed" if result.get("status") == "FAILED" else "retry"] += 1
            continue

        record_webhook_delivery(
            db_path,
            event_id=event["event_id"],
            delivered=True,
            response_status=status_code,
            error="",
            max_attempts=max_attempts,
        )
        summary["delivered"] += 1
    return summary
