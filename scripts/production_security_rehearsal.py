from __future__ import annotations

"""Static production deployment and fail-closed profile rehearsal.

This validates repository configuration contracts. It does not claim that a
Docker daemon, real TLS certificate, reverse proxy, or external backup target
was exercised.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.auth import parse_api_tokens
from app.services.security_profile import enforce_security_profile



def run_rehearsal(root: Path = ROOT) -> dict[str, Any]:
    compose = yaml.safe_load((root / "docker-compose.production.yml").read_text(encoding="utf-8"))
    services = compose.get("services") or {}
    app = services.get("vulnflow") or {}
    proxy = services.get("proxy") or {}
    app_env = app.get("environment") or {}
    nginx = (root / "deploy/nginx/vulnflow.conf").read_text(encoding="utf-8")
    env_example = (root / ".env.production.example").read_text(encoding="utf-8")

    checks = {
        "app_not_directly_published": not app.get("ports") and "8000" in [str(item) for item in app.get("expose") or []],
        "production_profile_enabled": str(app_env.get("VULNFLOW_SECURITY_PROFILE")) == "production",
        "secure_cookie_enabled": str(app_env.get("VULNFLOW_COOKIE_SECURE")) == "1",
        "session_binding_enabled": str(app_env.get("VULNFLOW_AUTH_SESSION_BINDING")) in {"user-agent", "strict"},
        "runtime_dependency_enforcement": str(app_env.get("VULNFLOW_RUNTIME_DEPENDENCY_POLICY")) == "enforce",
        "private_http_egress_disabled": str(app_env.get("VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS")) == "0",
        "outbound_response_bounded": "1048576" in str(app_env.get("VULNFLOW_OUTBOUND_MAX_RESPONSE_BYTES") or ""),
        "outbound_allowlist_documented": "VULNFLOW_OUTBOUND_HOST_ALLOWLIST" in env_example,
        "intelligence_hosts_allowlisted": all(
            host in env_example for host in ("api.osv.dev", "www.cisa.gov", "api.first.org")
        ),
        "intelligence_response_limits_configured": all(
            name in app_env for name in (
                "VULNFLOW_INTEL_MAX_RESPONSE_BYTES", "VULNFLOW_OSV_MAX_RESPONSE_BYTES"
            )
        ),
        "private_smtp_default_disabled": str(app_env.get("VULNFLOW_SMTP_ALLOW_PRIVATE_NETWORKS")) in {"0", "${VULNFLOW_SMTP_ALLOW_PRIVATE_NETWORKS:-0}"},
        "plain_smtp_disabled": str(app_env.get("VULNFLOW_SMTP_ALLOW_PLAIN")) == "0",
        "smtp_allowlist_documented": "VULNFLOW_SMTP_HOST_ALLOWLIST" in env_example,
        "signed_audit_and_backup_required": str(app_env.get("VULNFLOW_AUDIT_REQUIRE_SIGNATURE")) == "1" and str(app_env.get("VULNFLOW_BACKUP_REQUIRE_SIGNATURE")) == "1",
        "external_backup_mounted": any(str(item).endswith(":/app/external-backups") for item in app.get("volumes") or []),
        "proxy_publishes_tls": "443:443" in [str(item) for item in proxy.get("ports") or []],
        "certificates_read_only": any(str(item).endswith(":/etc/nginx/certs:ro") for item in proxy.get("volumes") or []),
        "tls_protocol_floor": "ssl_protocols TLSv1.2 TLSv1.3;" in nginx,
        "hsts_enabled": "Strict-Transport-Security" in nginx and "always;" in nginx,
        "forwarded_https": "proxy_set_header X-Forwarded-Proto https;" in nginx,
        "proxy_headers_trusted_only_on_internal_network": str(app_env.get("FORWARDED_ALLOW_IPS")) == "*" and bool(((compose.get("networks") or {}).get("backend") or {}).get("internal")),
        "forwarded_for_overwritten_at_edge": "proxy_set_header X-Forwarded-For $remote_addr;" in nginx and "$proxy_add_x_forwarded_for" not in nginx,
        "duplicate_edge_headers_hidden": all(f"proxy_hide_header {name};" in nginx for name in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy")),
        "backend_network_internal": bool(((compose.get("networks") or {}).get("backend") or {}).get("internal")),
        "production_env_has_no_real_secrets": "replace-with" in env_example and "vulnflow.example.com" in env_example,
    }

    profile_values = {
        "SECURITY_PROFILE": "production",
        "PUBLIC_BASE_URL": "https://vulnflow.example.test",
        "COOKIE_SECURE": True,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "AUTH_SESSION_BINDING": "user-agent",
        "AUTH_SESSION_IDLE_MINUTES": 60,
        "RUNTIME_DEPENDENCY_POLICY": "enforce",
        "OUTBOUND_ALLOW_PRIVATE_NETWORKS": False,
        "OUTBOUND_HOST_ALLOWLIST": "api.osv.dev,www.cisa.gov,api.first.org,*.atlassian.net",
        "SMTP_ALLOW_PRIVATE_NETWORKS": False,
        "SMTP_HOST_ALLOWLIST": "smtp.example.com",
        "SMTP_ALLOW_PLAIN": False,
        "EVIDENCE_REQUIRE_CLEAN": True,
        "EVIDENCE_SCANNER_MODE": "builtin",
        "AUDIT_REQUIRE_SIGNATURE": True,
        "AUDIT_SIGNING_KEY": "rehearsal-audit-key",
        "SIGNING_KEYS_JSON": "",
        "AUDIT_ACTIVE_KEY_ID": "",
        "BACKUP_REQUIRE_SIGNATURE": True,
        "BACKUP_SIGNING_KEY": "rehearsal-backup-key",
        "BACKUP_ACTIVE_KEY_ID": "",
        "CURSOR_SIGNING_KEY_CONFIGURED": True,
        "BACKUP_INTERVAL_HOURS": 12,
        "EXTERNAL_BACKUP_DIR": root / ".rehearsal-external-backups",
    }
    tokens = parse_api_tokens(
        '{"rehearsal":{"token":"0123456789abcdef","role":"viewer","projects":["default"]}}'
    )
    checks["profile_evaluator_passes_secure_fixture"] = enforce_security_profile(
        profile_values, tokens=tokens
    ).passed
    return {
        "format": "vulnflow-production-security-rehearsal/1",
        "passed": all(checks.values()),
        "checks": checks,
        "limitations": [
            "Docker daemon and container image were not executed by this static rehearsal.",
            "No real public certificate, DNS name, SMTP/Jira endpoint, or external backup mount was exercised.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output")
    args = parser.parse_args()
    report = run_rehearsal()
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(payload)
    if args.json_output:
        Path(args.json_output).write_text(payload + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
