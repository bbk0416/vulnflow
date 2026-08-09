from __future__ import annotations

"""Offline control database backup, validation, and restore CLI."""

import argparse
import json
from pathlib import Path
import sys

from app.core.settings import CONTROL_DB_PATH, PROJECTS_DIR
from app.services.control_recovery import (
    create_control_recovery_bundle,
    restore_control_recovery_bundle,
    validate_control_recovery_bundle,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VulnFlow control.db를 세션 없이 백업·검증·복원합니다. 복원은 서비스를 중지한 상태에서 실행하세요."
    )
    parser.add_argument("--db", type=Path, default=CONTROL_DB_PATH, help="control.db 경로")
    parser.add_argument("--projects-dir", type=Path, default=PROJECTS_DIR, help="프로젝트 저장소 루트")
    parser.add_argument("--signing-key", default="", help="선택 HMAC 키")
    parser.add_argument("--signing-key-id", default=None, help="선택 HMAC 키 ID")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="제어 DB 복구 번들 생성")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--actor", default="cli-admin")

    validate = sub.add_parser("validate", help="제어 DB 복구 번들 검증")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--require-signature", action="store_true")

    restore = sub.add_parser("restore", help="제어 DB 복구 번들 복원")
    restore.add_argument("--bundle", type=Path, required=True)
    restore.add_argument("--actor", default="cli-admin")
    restore.add_argument("--require-signature", action="store_true")
    restore.add_argument("--confirm", required=True, help="정확히 RESTORE-CONTROL 입력")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            result = create_control_recovery_bundle(
                args.db,
                args.output,
                created_by=args.actor,
                signing_key=args.signing_key,
                signing_key_id=args.signing_key_id,
            )
        elif args.command == "validate":
            result = validate_control_recovery_bundle(
                args.bundle,
                signing_key=args.signing_key,
                require_signature=args.require_signature,
            )
        else:
            if args.confirm != "RESTORE-CONTROL":
                raise ValueError("제어 DB 복원에는 --confirm RESTORE-CONTROL이 필요합니다.")
            result = restore_control_recovery_bundle(
                args.db,
                args.bundle,
                actor=args.actor,
                projects_dir=args.projects_dir,
                signing_key=args.signing_key,
                require_signature=args.require_signature,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    except (ValueError, OSError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
