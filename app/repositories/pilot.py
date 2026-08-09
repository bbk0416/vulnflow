from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

_DEFAULT_PROFILE: dict[str, Any] = {
    "customer_name": "",
    "engagement_name": "",
    "contact_name": "",
    "contact_email": "",
    "scope_notes": "",
    "default_due_days": 30,
    "report_footer": "",
    "updated_by": "",
    "updated_at": "",
}


def _clean(value: Any, *, limit: int, field: str) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise ValueError(f"{field}은(는) 최대 {limit}자입니다.")
    return text


def get_pilot_profile(db_path: str | Path) -> dict[str, Any]:
    with read_connection(db_path, operation="get_pilot_profile") as conn:
        row = conn.execute(
            "SELECT * FROM pilot_project_profile WHERE singleton_id=1"
        ).fetchone()
    if row is None:
        return dict(_DEFAULT_PROFILE)
    item = dict(row)
    item.pop("singleton_id", None)
    return {**_DEFAULT_PROFILE, **item}


def save_pilot_profile(
    db_path: str | Path,
    *,
    customer_name: str,
    engagement_name: str,
    contact_name: str = "",
    contact_email: str = "",
    scope_notes: str = "",
    default_due_days: int = 30,
    report_footer: str = "",
    actor: str,
) -> dict[str, Any]:
    customer = _clean(customer_name, limit=120, field="고객사 이름")
    engagement = _clean(engagement_name, limit=160, field="프로젝트 이름")
    contact = _clean(contact_name, limit=120, field="담당자 이름")
    email = _clean(contact_email, limit=254, field="담당자 이메일")
    notes = _clean(scope_notes, limit=4000, field="진단 범위")
    footer = _clean(report_footer, limit=1000, field="보고서 하단 문구")
    if not customer:
        raise ValueError("고객사 이름을 입력해야 합니다.")
    if not engagement:
        raise ValueError("프로젝트 이름을 입력해야 합니다.")
    if email and not _EMAIL_RE.fullmatch(email):
        raise ValueError("담당자 이메일 형식이 올바르지 않습니다.")
    due_days = int(default_due_days)
    if due_days < 1 or due_days > 365:
        raise ValueError("기본 조치기한은 1일 이상 365일 이하여야 합니다.")
    now = utc_now()
    with write_transaction(db_path, operation="save_pilot_profile") as conn:
        conn.execute(
            """
            INSERT INTO pilot_project_profile(
                singleton_id,customer_name,engagement_name,contact_name,contact_email,
                scope_notes,default_due_days,report_footer,updated_by,updated_at
            ) VALUES(1,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(singleton_id) DO UPDATE SET
                customer_name=excluded.customer_name,
                engagement_name=excluded.engagement_name,
                contact_name=excluded.contact_name,
                contact_email=excluded.contact_email,
                scope_notes=excluded.scope_notes,
                default_due_days=excluded.default_due_days,
                report_footer=excluded.report_footer,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (customer, engagement, contact, email, notes, due_days, footer, actor, now),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="PILOT_PROFILE_UPDATED",
            summary=f"파일럿 프로젝트 정보 변경: {customer} / {engagement}",
            details={
                "customer_name": customer,
                "engagement_name": engagement,
                "contact_configured": bool(contact or email),
                "default_due_days": due_days,
            },
            actor=actor,
            conn=conn,
        )
    return get_pilot_profile(db_path)
