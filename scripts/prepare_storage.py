from __future__ import annotations

"""Prepare VulnFlow's split control/default-project storage layout."""

import argparse
import json
from pathlib import Path

from app.core.database_schema import init_db
from app.core.settings import (
    CONTROL_DB_PATH,
    DATA_DIR,
    DEFAULT_PROJECT_DB_PATH,
    EVIDENCE_DIR,
    EXPORT_DIR,
    IMPORT_PREVIEW_DIR,
    LEGACY_DB_PATH,
    LEGACY_EVIDENCE_DIR,
    LEGACY_EXPORT_DIR,
    LEGACY_IMPORT_PREVIEW_DIR,
    LEGACY_RECOVERY_DIR,
    RECOVERY_DIR,
)
from app.services.storage_layout import prepare_split_storage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="제어 DB와 기본 프로젝트 DB 저장소를 준비합니다.")
    parser.add_argument("--control-db", type=Path, default=CONTROL_DB_PATH)
    parser.add_argument("--default-project-db", type=Path, default=DEFAULT_PROJECT_DB_PATH)
    parser.add_argument("--legacy-db", type=Path, default=LEGACY_DB_PATH)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = prepare_split_storage(
        control_database=args.control_db,
        default_project_database=args.default_project_db,
        legacy_database=args.legacy_db,
        data_directory=args.data_dir,
        directory_migrations=(
            (LEGACY_EVIDENCE_DIR, EVIDENCE_DIR),
            (LEGACY_EXPORT_DIR, EXPORT_DIR),
            (LEGACY_IMPORT_PREVIEW_DIR, IMPORT_PREVIEW_DIR),
            (LEGACY_RECOVERY_DIR, RECOVERY_DIR),
        ),
        init_db_fn=init_db,
    )
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
