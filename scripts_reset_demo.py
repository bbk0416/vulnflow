from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.core.storage import init_db


def _enabled(name: str) -> bool:
    return os.getenv(name, "0").strip().lower() in {"1", "true", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete the local demo database. This command is disabled outside demo mode."
    )
    parser.add_argument(
        "--confirm",
        required=True,
        help="Enter RESET-DEMO to confirm destructive deletion.",
    )
    args = parser.parse_args()
    if not _enabled("VULNFLOW_DEMO_MODE"):
        raise SystemExit("VULNFLOW_DEMO_MODE=1인 로컬 데모에서만 초기화할 수 있습니다.")
    if args.confirm != "RESET-DEMO":
        raise SystemExit("초기화하려면 --confirm RESET-DEMO를 정확히 입력하세요.")

    root = Path(__file__).resolve().parent
    db = Path(os.getenv("VULNFLOW_DB", str(root / "data" / "vulnflow.db")))
    for candidate in [db, Path(str(db) + "-wal"), Path(str(db) + "-shm")]:
        if candidate.exists():
            candidate.unlink()
    init_db(db)
    print(f"데모 초기화 완료: {db}")
    print("데모 모드로 서버를 다시 시작하면 합성 샘플 데이터가 적재됩니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
