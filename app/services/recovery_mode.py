from __future__ import annotations

"""Read-only recovery-mode policy and diagnostics.

The application enters this mode when startup integrity checks cannot establish
that the audit chain or evidence store is trustworthy. Normal mutation and
background processing stop, while authenticated operators can still inspect,
export, validate, and restore known-good data.
"""

from typing import Any, Mapping

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
RECOVERY_WRITE_PATHS = frozenset(
    {
        "/restore-backup",
        "/validate-recovery-bundle",
        "/restore-recovery-bundle",
        "/api/v1/recovery/validate",
        "/api/v1/recovery/restore",
        "/login",
        "/logout",
        "/projects/switch",
        "/admin/projects/integrity-check",
    }
)


def _normalized_report(name: str, report: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = dict(report or {})
    payload.setdefault("valid", False)
    issues = payload.get("issues")
    if not isinstance(issues, list):
        issues = [str(issues)] if issues else []
    payload["issues"] = [str(item) for item in issues if str(item).strip()]
    payload["check"] = name
    return payload


def failed_integrity_report(name: str, exc: BaseException) -> dict[str, Any]:
    """Convert an integrity-check exception into a safe operator diagnostic."""
    return {
        "check": name,
        "valid": False,
        "issues": [f"{name} 검사 실행 실패: {type(exc).__name__}"],
        "error_type": type(exc).__name__,
    }


def build_recovery_mode(
    *,
    evidence_integrity: Mapping[str, Any] | None,
    audit_integrity: Mapping[str, Any] | None,
) -> dict[str, Any]:
    evidence = _normalized_report("evidence", evidence_integrity)
    audit = _normalized_report("audit", audit_integrity)
    failed = [item for item in (evidence, audit) if not bool(item.get("valid"))]
    reasons: list[str] = []
    for item in failed:
        label = "증거 저장소" if item["check"] == "evidence" else "감사 체인"
        issues = item.get("issues") or []
        reasons.append(f"{label}: {issues[0] if issues else '무결성을 확인할 수 없습니다.'}")
    return {
        "active": bool(failed),
        "read_only": bool(failed),
        "reasons": reasons,
        "evidence_integrity": evidence,
        "audit_integrity": audit,
        "allowed_write_paths": sorted(RECOVERY_WRITE_PATHS),
    }


def recovery_mode_summary(mode: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = dict(mode or {})
    return {
        "active": bool(payload.get("active")),
        "read_only": bool(payload.get("read_only")),
        "reasons": [str(item) for item in (payload.get("reasons") or [])],
    }


def recovery_write_allowed(method: str, path: str) -> bool:
    normalized_method = str(method or "").upper()
    if normalized_method in SAFE_METHODS:
        return True
    return str(path or "") in RECOVERY_WRITE_PATHS


__all__ = [
    "SAFE_METHODS",
    "RECOVERY_WRITE_PATHS",
    "build_recovery_mode",
    "failed_integrity_report",
    "recovery_mode_summary",
    "recovery_write_allowed",
]
