from __future__ import annotations

"""Startup preflight for interrupted offline deployment history recovery.

The signed offline launcher invokes this module before importing the web
application.  A single authenticated recovery journal is completed
fail-closed.  Unsafe, multiple, or legacy unauthenticated journals block
startup and require explicit operator review through the management CLI.
"""

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.offline_deployment_activation import absolute_path, deployment_operation_lock
    from scripts.offline_deployment_recovery import (
        inspect_interrupted_history_recovery,
        recover_interrupted_history_recovery,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path, deployment_operation_lock
    from offline_deployment_recovery import (
        inspect_interrupted_history_recovery,
        recover_interrupted_history_recovery,
    )


def preflight_deployment_history(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    with deployment_operation_lock(target):
        status = inspect_interrupted_history_recovery(target)
        if not status["pending"]:
            return {"target": str(target), "status": "clean", "recovered": False}
        if status["count"] != 1:
            raise RuntimeError("offline deployment startup blocked by multiple recovery journals")
        transaction = status["transactions"][0]
        if not transaction.get("authenticated"):
            raise RuntimeError(
                "offline deployment startup blocked by an unauthenticated legacy recovery journal; "
                "run manage_offline_deployments.py recover-interrupted with explicit legacy confirmation"
            )
        recovered = recover_interrupted_history_recovery(target)
        if recovered["status"]["pending"]:
            raise RuntimeError("offline deployment recovery journal remains after startup preflight")
        return {"target": str(target), "status": "recovered", "recovered": True, "recovery": recovered["result"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover an authenticated interrupted deployment-history transaction before startup.")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(json.dumps(preflight_deployment_history(Path(args.target)), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
