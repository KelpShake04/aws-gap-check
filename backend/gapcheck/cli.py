"""관리 명령. 웹에서 가입할 수 없고 관리자가 이 명령으로 사용자를 만든다.

    docker compose exec app python -m gapcheck.cli create-user <이메일>
"""
from __future__ import annotations

import argparse
import sys

from . import auth
from .common import ApiError, utcnow


def main(argv=None, store=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gapcheck.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-user", help="사용자를 만들고 임시 비밀번호를 출력한다")
    create.add_argument("email")
    args = parser.parse_args(argv)

    if store is None:
        from .app import store_from_env
        store = store_from_env()
    if store.get_user_by_email(auth.normalize_email(args.email)):
        print("이미 있는 이메일입니다.", file=sys.stderr)
        return 1
    try:
        user, password = auth.create_user(store, args.email, utcnow())
    except ApiError as err:
        print(err.message, file=sys.stderr)
        return 1
    print(f"사용자를 만들었습니다: {user['email']}")
    print(f"임시 비밀번호: {password}")
    print("첫 로그인 때 새 비밀번호로 바꿔야 합니다. 임시 비밀번호는 다시 볼 수 없습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
