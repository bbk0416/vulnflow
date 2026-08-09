from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

from app.services.collaboration import validate_jira_config
from app.services.integration_diagnostics_common import DiagnosticResult, elapsed_ms
from app.services.outbound_http import (
    OutboundError,
    OutboundPolicyError,
    OutboundResponseTooLarge,
    request_outbound,
)


def diagnose_jira_connection(
    config: dict[str, Any],
    secret: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (),
    max_response_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        normalized = validate_jira_config(
            config, secret_configured=bool(secret.get("api_token"))
        )
    except (TypeError, ValueError) as exc:
        return DiagnosticResult(
            "JIRA", False, "configuration", str(exc), elapsed_ms(started), {}
        ).as_dict()

    details: dict[str, Any] = {
        "base_url": normalized["base_url"],
        "project_key": normalized["project_key"],
        "issue_type": normalized["issue_type"],
        "write_performed": False,
    }
    auth = (normalized["email"], secret.get("api_token", ""))
    headers = {"Accept": "application/json"}
    try:
        myself = request_outbound(
            "GET",
            f"{normalized['base_url']}/rest/api/3/myself",
            basic_auth=auth,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
        )
        details["myself_status"] = int(myself.status_code)
        if myself.status_code in {401, 403}:
            return DiagnosticResult(
                "JIRA",
                False,
                "authentication",
                "Jira 인증에 실패했습니다. 계정 이메일과 API 토큰을 확인하세요.",
                elapsed_ms(started),
                details,
            ).as_dict()
        if not 200 <= myself.status_code < 300:
            return DiagnosticResult(
                "JIRA",
                False,
                "account",
                f"Jira 계정 확인 요청이 HTTP {myself.status_code}로 실패했습니다.",
                elapsed_ms(started),
                details,
            ).as_dict()

        project = request_outbound(
            "GET",
            f"{normalized['base_url']}/rest/api/3/project/{quote(normalized['project_key'], safe='')}",
            basic_auth=auth,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
        )
        details["project_status"] = int(project.status_code)
        if project.status_code == 404:
            return DiagnosticResult(
                "JIRA",
                False,
                "project",
                "설정한 Jira 프로젝트를 찾지 못했습니다. 프로젝트 키와 계정 권한을 확인하세요.",
                elapsed_ms(started),
                details,
            ).as_dict()
        if project.status_code == 403:
            return DiagnosticResult(
                "JIRA",
                False,
                "authorization",
                "Jira 프로젝트 조회 권한이 없습니다.",
                elapsed_ms(started),
                details,
            ).as_dict()
        if not 200 <= project.status_code < 300:
            return DiagnosticResult(
                "JIRA",
                False,
                "project",
                f"Jira 프로젝트 확인 요청이 HTTP {project.status_code}로 실패했습니다.",
                elapsed_ms(started),
                details,
            ).as_dict()
        return DiagnosticResult(
            "JIRA",
            True,
            "authorized",
            "Jira 계정 인증과 프로젝트 조회 권한을 확인했습니다. 이슈는 생성하지 않았습니다.",
            elapsed_ms(started),
            details,
        ).as_dict()
    except (OutboundPolicyError, OutboundResponseTooLarge):
        return DiagnosticResult(
            "JIRA",
            False,
            "outbound_policy",
            "Jira 주소가 외부 통신 보안 정책에 의해 차단됐습니다.",
            elapsed_ms(started),
            details,
        ).as_dict()
    except OutboundError:
        return DiagnosticResult(
            "JIRA",
            False,
            "connection",
            "Jira에 연결하지 못했습니다. DNS, 방화벽과 TLS 설정을 확인하세요.",
            elapsed_ms(started),
            details,
        ).as_dict()
