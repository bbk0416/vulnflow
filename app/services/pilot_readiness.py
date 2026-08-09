from __future__ import annotations

from typing import Any, Iterable, Mapping


def _check(
    key: str,
    label: str,
    passed: bool,
    detail: str,
    action_url: str,
    *,
    required: bool,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "passed": bool(passed),
        "status": "PASS" if passed else "PENDING",
        "detail": detail,
        "action_url": action_url,
        "required": required,
    }


def build_pilot_readiness(
    *,
    profile: Mapping[str, Any],
    finding_count: int,
    import_count: int,
    member_count: int,
    integrity_status: str,
    backup_count: int,
    recovery_drill_passed: bool,
    integrations: Iterable[Mapping[str, Any]],
    cookie_secure: bool,
    public_base_url: str,
) -> dict[str, Any]:
    profile_ready = bool(
        str(profile.get("customer_name") or "").strip()
        and str(profile.get("engagement_name") or "").strip()
    )
    integration_enabled = any(bool(item.get("enabled")) for item in integrations)
    secure_public = bool(cookie_secure and str(public_base_url or "").lower().startswith("https://"))
    checks = [
        _check(
            "profile",
            "고객사·프로젝트 정보",
            profile_ready,
            "보고서에 들어갈 고객사명과 프로젝트명을 설정합니다.",
            "/pilot#profile",
            required=True,
        ),
        _check(
            "members",
            "사용자 배정",
            int(member_count) > 0,
            f"현재 프로젝트 접근 사용자 {int(member_count)}명",
            "/projects",
            required=True,
        ),
        _check(
            "integrity",
            "데이터 무결성",
            str(integrity_status or "").upper() == "HEALTHY",
            f"현재 상태: {str(integrity_status or 'UNCHECKED').upper()}",
            "/projects",
            required=True,
        ),
        _check(
            "backup",
            "복구 가능한 백업",
            int(backup_count) > 0,
            f"확인된 복구 번들 {int(backup_count)}개",
            "/projects",
            required=True,
        ),
        _check(
            "scanner_data",
            "스캐너 데이터 입력",
            int(import_count) > 0 or int(finding_count) > 0,
            f"가져오기 {int(import_count)}회 · 취약점 {int(finding_count)}건",
            "/upload",
            required=True,
        ),
        _check(
            "recovery_drill",
            "복원 리허설",
            bool(recovery_drill_passed),
            "백업이 실제로 복원되는지 격리 환경에서 확인합니다.",
            "/projects",
            required=False,
        ),
        _check(
            "collaboration",
            "이메일 또는 Jira 연동",
            integration_enabled,
            "기한·검증·상태 변경을 담당자에게 자동 전달합니다.",
            "/integrations",
            required=False,
        ),
        _check(
            "transport",
            "HTTPS 운영 설정",
            secure_public,
            "공개 운영에서는 HTTPS URL과 Secure 쿠키를 함께 사용합니다.",
            "/system",
            required=False,
        ),
    ]
    required = [item for item in checks if item["required"]]
    recommended = [item for item in checks if not item["required"]]
    required_passed = sum(1 for item in required if item["passed"])
    total_passed = sum(1 for item in checks if item["passed"])
    return {
        "launch_ready": required_passed == len(required),
        "required_passed": required_passed,
        "required_total": len(required),
        "recommended_passed": sum(1 for item in recommended if item["passed"]),
        "recommended_total": len(recommended),
        "score_percent": round(total_passed * 100 / len(checks)) if checks else 100,
        "checks": checks,
    }
