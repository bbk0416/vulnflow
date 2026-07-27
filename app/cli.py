from __future__ import annotations

"""Installed console entry point for VulnFlow."""

import os

import uvicorn


def main() -> None:
    host = os.getenv("VULNFLOW_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("VULNFLOW_PORT", "8000") or 8000)
    log_level = os.getenv("VULNFLOW_LOG_LEVEL", "info").strip().lower() or "info"
    uvicorn.run("app.main:app", host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    main()
