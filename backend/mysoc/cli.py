"""Command-line admin tasks.

  python -m mysoc.cli create-admin USERNAME     (prompts for a password)
  python -m mysoc.cli reset-mfa USERNAME
  python -m mysoc.cli init
"""

import argparse
import getpass
import sys

from sqlalchemy import delete, select

from .bootstrap import bootstrap, create_user
from .db import init_db, session_scope
from .models import AuthSession, User
from .security.passwords import password_problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mysoc")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-admin", help="create an admin account")
    c.add_argument("username")
    r = sub.add_parser("reset-mfa", help="remove a user's authenticator (they set it up again at next sign-in)")
    r.add_argument("username")
    sub.add_parser("init", help="create tables, first admin and built-in rules")
    args = ap.parse_args(argv)

    if args.cmd == "init":
        bootstrap()
        return 0
    init_db()
    username = args.username.strip().lower()
    with session_scope() as s:
        existing = s.scalar(select(User).where(User.username == username))
        if args.cmd == "create-admin":
            if existing:
                print(f"{username} already exists.", file=sys.stderr)
                return 1
            pw = getpass.getpass("Password: ")
            if problems := password_problems(pw, username):
                print(" ".join(problems), file=sys.stderr)
                return 1
            if getpass.getpass("Again: ") != pw:
                print("Passwords don't match.", file=sys.stderr)
                return 1
            create_user(s, username, pw, "admin", "Administrator")
            print(f"Admin {username} created. You'll set up an authenticator app at first sign-in.")
        elif args.cmd == "reset-mfa":
            if not existing:
                print(f"No user {username}.", file=sys.stderr)
                return 1
            existing.mfa_enabled, existing.mfa_secret, existing.mfa_last_step = False, None, 0
            s.execute(delete(AuthSession).where(AuthSession.user_id == existing.id))
            print(f"Authenticator removed for {username}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
