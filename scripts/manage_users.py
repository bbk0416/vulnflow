from __future__ import annotations

"""Create and manage database-backed VulnFlow browser users."""

import argparse
from getpass import getpass
import json
from pathlib import Path
import sys

from app.core.database_schema import init_db
from app.core.settings import CONTROL_DB_PATH
from app.repositories.audit import add_audit_event
from app.services.accounts import (
    create_user,
    list_users,
    normalize_username,
    revoke_user_sessions,
    set_user_active,
    set_user_password,
    unlock_user,
)


def _password(args: argparse.Namespace) -> str:
    if getattr(args, "password_stdin", False):
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise ValueError("표준 입력에서 비밀번호를 읽지 못했습니다.")
        return value
    first = getpass("새 비밀번호: ")
    second = getpass("새 비밀번호 확인: ")
    if first != second:
        raise ValueError("비밀번호 확인이 일치하지 않습니다.")
    return first


def _print_user(user: dict) -> None:
    safe = {key: value for key, value in user.items() if key != "password_hash"}
    print(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))


def _audit(db_path: Path, event_type: str, summary: str, details: dict) -> None:
    add_audit_event(
        db_path,
        finding_id=None,
        event_type=event_type,
        summary=summary,
        details=details,
        actor="cli-admin",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VulnFlow DB 사용자 계정을 관리합니다. 비밀번호 원문은 저장하지 않습니다."
    )
    parser.add_argument("--db", type=Path, default=CONTROL_DB_PATH, help="SQLite DB 경로")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="새 사용자 생성")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=("viewer", "operator", "approver", "admin"), default="viewer")
    create.add_argument("--password-stdin", action="store_true", help="첫 번째 표준 입력 줄에서 비밀번호 읽기")

    sub.add_parser("list", help="사용자 목록")

    for name, help_text in (("enable", "사용자 활성화"), ("disable", "사용자 비활성화"), ("unlock", "로그인 실패 제한 기록 초기화"), ("revoke-sessions", "활성 세션 종료")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--username", required=True)

    password = sub.add_parser("set-password", help="비밀번호 변경 및 기존 세션 종료")
    password.add_argument("--username", required=True)
    password.add_argument("--password-stdin", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db_path = Path(args.db)
    init_db(db_path)
    try:
        if args.command == "create":
            user = create_user(
                db_path,
                username=args.username,
                password=_password(args),
                role=args.role,
                actor="cli-admin",
            )
            _audit(
                db_path,
                "USER_CREATED",
                f"사용자 계정 생성: {user['username']}",
                {"username": user["username"], "role": user["role"]},
            )
            _print_user(user)
        elif args.command == "list":
            print(json.dumps(list_users(db_path), ensure_ascii=False, indent=2, sort_keys=True))
        elif args.command == "enable":
            user = set_user_active(db_path, username=args.username, active=True, actor="cli-admin")
            _audit(db_path, "USER_STATUS_CHANGED", f"사용자 계정 활성화: {user['username']}", {"username": user["username"], "active": True})
            _print_user(user)
        elif args.command == "disable":
            user = set_user_active(db_path, username=args.username, active=False, actor="cli-admin")
            _audit(db_path, "USER_STATUS_CHANGED", f"사용자 계정 비활성화: {user['username']}", {"username": user["username"], "active": False})
            _print_user(user)
        elif args.command == "unlock":
            user = unlock_user(db_path, username=args.username, actor="cli-admin")
            _audit(db_path, "USER_LOGIN_ATTEMPTS_CLEARED", f"사용자 로그인 실패 기록 초기화: {user['username']}", {"username": user["username"]})
            _print_user(user)
        elif args.command == "set-password":
            user = set_user_password(
                db_path,
                username=args.username,
                password=_password(args),
                actor="cli-admin",
            )
            _audit(db_path, "USER_PASSWORD_RESET", f"사용자 비밀번호 재설정: {user['username']}", {"username": user["username"]})
            _print_user(user)
        elif args.command == "revoke-sessions":
            username = normalize_username(args.username)
            count = revoke_user_sessions(db_path, username)
            _audit(db_path, "USER_SESSIONS_REVOKED", f"사용자 세션 종료: {username}", {"username": username, "session_count": count})
            print(json.dumps({"username": username, "revoked_sessions": count}, ensure_ascii=False))
        else:
            parser.error("지원하지 않는 명령입니다.")
    except (ValueError, KeyError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
