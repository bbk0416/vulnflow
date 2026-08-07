from __future__ import annotations

"""Fail-closed runtime security profile evaluation.

The development profile preserves local test ergonomics.  Pilot reports unsafe
settings without preventing startup.  Production refuses to start when a
minimum recoverable HTTPS deployment contract is not met.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class SecurityProfileFinding:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class SecurityProfileReport:
    profile: str
    findings: tuple[SecurityProfileFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "passed": self.passed,
            "findings": [
                {"code": item.code, "message": item.message}
                for item in self.findings
            ],
        }


def _enabled(values: Mapping[str, Any], name: str) -> bool:
    return bool(values.get(name, False))


def _nonempty(values: Mapping[str, Any], name: str) -> bool:
    return bool(str(values.get(name, "") or "").strip())


def _has_explicit_token_scopes(tokens: Mapping[str, Mapping[str, Any]]) -> bool:
    return all(tuple(item.get("projects") or ()) for item in tokens.values())


def evaluate_security_profile(
    values: Mapping[str, Any],
    *,
    tokens: Mapping[str, Mapping[str, Any]] | None = None,
) -> SecurityProfileReport:
    profile = str(values.get("SECURITY_PROFILE", "development") or "development").strip().lower()
    if profile not in {"development", "pilot", "production"}:
        return SecurityProfileReport(
            profile,
            (SecurityProfileFinding("profile.invalid", "지원하지 않는 보안 프로필입니다."),),
        )
    if profile == "development":
        return SecurityProfileReport(profile, ())

    findings: list[SecurityProfileFinding] = []
    public_url = str(values.get("PUBLIC_BASE_URL", "") or "").strip()
    parsed_url = urlparse(public_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        findings.append(SecurityProfileFinding("https.public_url", "VULNFLOW_PUBLIC_BASE_URL은 https URL이어야 합니다."))
    if not _enabled(values, "COOKIE_SECURE"):
        findings.append(SecurityProfileFinding("cookie.secure", "Secure 세션 쿠키를 활성화해야 합니다."))
    if _enabled(values, "DEMO_MODE") or _enabled(values, "ALLOW_LOCAL_ADMIN_FALLBACK"):
        findings.append(SecurityProfileFinding("demo.disabled", "데모 모드와 로컬 관리자 fallback을 비활성화해야 합니다."))
    if str(values.get("AUTH_SESSION_BINDING", "off") or "off") == "off":
        findings.append(SecurityProfileFinding("session.binding", "세션 user-agent 결합을 활성화해야 합니다."))
    if int(values.get("AUTH_SESSION_IDLE_MINUTES", 0) or 0) <= 0:
        findings.append(SecurityProfileFinding("session.idle_timeout", "세션 유휴 만료 시간을 설정해야 합니다."))
    if tokens and not _has_explicit_token_scopes(tokens):
        findings.append(SecurityProfileFinding("api.scope", "모든 API 토큰에 projects 범위를 명시해야 합니다."))
    if str(values.get("RUNTIME_DEPENDENCY_POLICY", "off") or "off").strip().lower() != "enforce":
        findings.append(SecurityProfileFinding("dependency.enforce", "운영 환경에서는 런타임 의존성 검증을 enforce로 설정해야 합니다."))
    if _enabled(values, "OUTBOUND_ALLOW_PRIVATE_NETWORKS"):
        findings.append(SecurityProfileFinding("outbound.private_networks", "운영 환경의 HTTP 외부 연동에서 사설·로컬 네트워크 접근을 허용하면 안 됩니다."))
    if _nonempty(values, "WEBHOOKS_JSON") and not _nonempty(values, "OUTBOUND_HOST_ALLOWLIST"):
        findings.append(SecurityProfileFinding("outbound.allowlist", "운영 웹훅에는 목적지 호스트 allowlist를 설정해야 합니다."))
    if _enabled(values, "SMTP_ALLOW_PLAIN"):
        findings.append(SecurityProfileFinding("smtp.plain", "운영 환경에서는 암호화되지 않은 SMTP를 허용하면 안 됩니다."))
    if _enabled(values, "SMTP_ALLOW_PRIVATE_NETWORKS") and not _nonempty(values, "SMTP_HOST_ALLOWLIST"):
        findings.append(SecurityProfileFinding("smtp.allowlist", "사설망 SMTP를 허용하려면 목적지 호스트 allowlist가 필요합니다."))
    if not _enabled(values, "EVIDENCE_REQUIRE_CLEAN") or str(values.get("EVIDENCE_SCANNER_MODE", "")) == "disabled":
        findings.append(SecurityProfileFinding("evidence.scanning", "증거파일 검사와 clean 판정을 강제해야 합니다."))
    if not _enabled(values, "AUDIT_REQUIRE_SIGNATURE") or not (
        _nonempty(values, "AUDIT_SIGNING_KEY")
        or (_nonempty(values, "SIGNING_KEYS_JSON") and _nonempty(values, "AUDIT_ACTIVE_KEY_ID"))
    ):
        findings.append(SecurityProfileFinding("audit.signature", "감사 로그 서명과 활성 키를 설정해야 합니다."))
    if not _enabled(values, "BACKUP_REQUIRE_SIGNATURE") or not (
        _nonempty(values, "BACKUP_SIGNING_KEY")
        or (_nonempty(values, "SIGNING_KEYS_JSON") and _nonempty(values, "BACKUP_ACTIVE_KEY_ID"))
    ):
        findings.append(SecurityProfileFinding("backup.signature", "백업 서명과 활성 키를 설정해야 합니다."))
    if not _enabled(values, "CURSOR_SIGNING_KEY_CONFIGURED"):
        findings.append(SecurityProfileFinding("cursor.key", "영속적인 cursor 서명 키를 명시적으로 설정해야 합니다."))
    if int(values.get("BACKUP_INTERVAL_HOURS", 0) or 0) <= 0:
        findings.append(SecurityProfileFinding("backup.schedule", "자동 백업 주기를 설정해야 합니다."))
    external = values.get("EXTERNAL_BACKUP_DIR")
    if external is None or not str(Path(external)).strip():
        findings.append(SecurityProfileFinding("backup.external", "외부 백업 디렉터리를 설정해야 합니다."))

    return SecurityProfileReport(profile, tuple(findings))


def enforce_security_profile(
    values: Mapping[str, Any],
    *,
    tokens: Mapping[str, Mapping[str, Any]] | None = None,
) -> SecurityProfileReport:
    report = evaluate_security_profile(values, tokens=tokens)
    if report.profile == "production" and not report.passed:
        details = "; ".join(f"{item.code}: {item.message}" for item in report.findings)
        raise RuntimeError(f"운영 보안 프로필 검증 실패: {details}")
    return report
