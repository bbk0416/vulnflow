from __future__ import annotations

"""Run read-only SMTP and Jira checks against saved project integration settings."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.integration_diagnostics import diagnose_saved_integration  # noqa: E402
from app.services.integration_crypto import IntegrationSecretError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path(os.getenv("VULNFLOW_DB", "data/vulnflow.db")))
    parser.add_argument("--channel", type=str.upper, choices=("EMAIL", "JIRA", "ALL"), default="ALL")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    key = os.getenv("VULNFLOW_INTEGRATION_SECRET_KEY", "")
    if len(key) < 32:
        print("VULNFLOW_INTEGRATION_SECRET_KEY must be at least 32 characters.", file=sys.stderr)
        return 2
    if not args.db.is_file():
        print(f"database not found: {args.db}", file=sys.stderr)
        return 2

    channels = ("EMAIL", "JIRA") if args.channel == "ALL" else (args.channel,)
    reports = []
    try:
        for channel in channels:
            reports.append(diagnose_saved_integration(
                args.db, channel=channel, master_key=key, timeout_seconds=max(1, args.timeout),
                allow_private_networks=os.getenv("VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS", "0").strip().lower() in {"1", "true", "yes"},
                host_allowlist=os.getenv("VULNFLOW_OUTBOUND_HOST_ALLOWLIST", ""),
                max_response_bytes=max(4096, int(os.getenv("VULNFLOW_OUTBOUND_MAX_RESPONSE_BYTES", str(1024 * 1024)) or (1024 * 1024))),
            ))
    except IntegrationSecretError:
        print("saved integration secret could not be decrypted with the configured master key", file=sys.stderr)
        return 2

    payload = {
        "format": "vulnflow-integration-connection-check/1",
        "database": str(args.db.resolve()),
        "reports": reports,
        "passed": all(item["ok"] for item in reports),
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    for item in reports:
        print(f"[{'PASS' if item['ok'] else 'FAIL'}] {item['channel']} {item['stage']}: {item['message']}")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
