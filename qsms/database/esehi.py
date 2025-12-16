"""
Admin/debug tool for inspecting all users in the QSMS database.

Shows:
- User info (id, username, hash, salt, pbkdf2_iter, timestamps)
- Login history (from AuthAudit)
- Stored keys (from Key)
- Optional message summary (counts only, not full message bodies)

USAGE (from project root):
    python -m qsms.database.admin_report
    python -m qsms.database.admin_report --include-messages
    python -m qsms.database.admin_report --user alice
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional

from .db_config import session_scope
from .models import User, AuthAudit, Key, Message


def get_user_details(
    username: str,
    include_messages: bool = False,
    message_limit: int = 50,
) -> Optional[Dict[str, Any]]:
    """
    Return detailed info about a single user.

    NOTE: This is an admin/debug function. Do NOT expose this to normal clients.
    """
    with session_scope() as s:
        user = (
            s.query(User)
            .filter(User.username == username)
            .one_or_none()
        )
        if user is None:
            return None

        # Login history (newest first)
        audits = (
            s.query(AuthAudit)
            .filter(AuthAudit.username == username)
            .order_by(AuthAudit.created_at.desc())
            .all()
        )

        # Keys for this user (newest first)
        keys = (
            s.query(Key)
            .filter(Key.user_id == user.id)
            .order_by(Key.created_at.desc())
            .all()
        )

        # Optional message summary
        messages_summary: Dict[str, Any] = {}
        if include_messages:
            # Inbox count
            inbox_q = (
                s.query(Message)
                .filter(Message.recipient == username)
            )
            inbox_count = inbox_q.count()

            # Outbox count
            outbox_q = (
                s.query(Message)
                .filter(Message.sender == username)
            )
            outbox_count = outbox_q.count()

            # Unread count (delivered_at is NULL)
            unread_q = (
                inbox_q.filter(Message.delivered_at.is_(None))
            )
            unread_count = unread_q.count()

            # Optionally fetch a few recent messages (metadata only)
            recent_msgs = (
                inbox_q
                .order_by(Message.created_at.desc(), Message.id.desc())
                .limit(message_limit)
                .all()
            )

            messages_summary = {
                "inbox_total": inbox_count,
                "outbox_total": outbox_count,
                "unread_inbox": unread_count,
                "recent_inbox": [
                    {
                        "id": m.id,
                        "created_at": m.created_at,
                        "sender": m.sender,
                        "nonce_len": len(m.nonce) if m.nonce is not None else 0,
                        "ciphertext_len": len(m.ciphertext) if m.ciphertext is not None else 0,
                    }
                    for m in recent_msgs
                ],
            }

        return {
            "user": {
                "id": user.id,
                "username": user.username,
                "password_hash_b64": user.password_hash_b64,
                "salt_b64": user.salt_b64,
                "pbkdf2_iter": user.pbkdf2_iter,
                "created_at": user.created_at,
                "last_login_at": user.last_login_at,
            },
            "logins": [
                {
                    "id": a.id,
                    "ok": a.ok,
                    "ip": a.ip,
                    "created_at": a.created_at,
                }
                for a in audits
            ],
            "keys": [
                {
                    "id": k.id,
                    "type": k.type,
                    "device_id": k.device_id,
                    "created_at": k.created_at,
                    "public_key_len": len(k.public_key) if k.public_key else 0,
                }
                for k in keys
            ],
            "messages": messages_summary,
        }


def get_all_users_details(
    include_messages: bool = False,
    message_limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Fetch detailed info for ALL users in the database.
    """
    with session_scope() as s:
        users = s.query(User).order_by(User.id).all()
        usernames = [u.username for u in users]

    # Fetch each user separately (keeps logic in one place)
    results: List[Dict[str, Any]] = []
    for username in usernames:
        details = get_user_details(username, include_messages, message_limit)
        if details is not None:
            results.append(details)
    return results


def _print_user_details(details: Dict[str, Any]) -> None:
    """Pretty-print user details to the console."""
    user = details["user"]
    logins = details["logins"]
    keys = details["keys"]
    messages = details.get("messages") or {}

    print("=" * 60)
    print(f"User: {user['username']} (id={user['id']})")
    print("-" * 60)
    print("Account:")
    print(f"  created_at     : {user['created_at']}")
    print(f"  last_login_at  : {user['last_login_at']}")
    print(f"  pbkdf2_iter    : {user['pbkdf2_iter']}")
    print(f"  password_hash  : {user['password_hash_b64']}")
    print(f"  salt_b64       : {user['salt_b64']}")

    print("\nLogin history (newest first):")
    if not logins:
        print("  (no login records)")
    else:
        for row in logins:
            status = "OK " if row["ok"] else "FAIL"
            print(
                f"  [{row['created_at']}] {status} "
                f"ip={row['ip']} id={row['id']}"
            )

    print("\nStored keys (newest first):")
    if not keys:
        print("  (no keys stored)")
    else:
        for row in keys:
            print(
                f"  id={row['id']} type={row['type']} "
                f"device={row['device_id']} created_at={row['created_at']} "
                f"public_key_len={row['public_key_len']}"
            )

    if messages:
        print("\nMessage summary:")
        print(f"  inbox_total    : {messages.get('inbox_total')}")
        print(f"  outbox_total   : {messages.get('outbox_total')}")
        print(f"  unread_inbox   : {messages.get('unread_inbox')}")
        recent = messages.get("recent_inbox") or []
        if recent:
            print("  recent_inbox (limited sample):")
            for m in recent:
                print(
                    f"    id={m['id']} from={m['sender']} "
                    f"at={m['created_at']} "
                    f"nonce_len={m['nonce_len']} "
                    f"ciphertext_len={m['ciphertext_len']}"
                )
        else:
            print("  recent_inbox   : (none)")
    print()  # extra newline


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Admin tool: show details for all users in the QSMS database."
    )
    parser.add_argument(
        "--user",
        help="Show details only for this username (optional).",
    )
    parser.add_argument(
        "--include-messages",
        action="store_true",
        help="Include message summary (counts and small sample).",
    )
    parser.add_argument(
        "--message-limit",
        type=int,
        default=50,
        help="Max number of recent inbox messages to show per user when --include-messages is set.",
    )

    args = parser.parse_args()

    if args.user:
        details = get_user_details(
            args.user,
            include_messages=args.include_messages,
            message_limit=args.message_limit,
        )
        if details is None:
            print(f"No such user: {args.user}")
            return
        _print_user_details(details)
    else:
        all_details = get_all_users_details(
            include_messages=args.include_messages,
            message_limit=args.message_limit,
        )
        if not all_details:
            print("No users found in the database.")
            return
        for details in all_details:
            _print_user_details(details)


if __name__ == "__main__":
    main()
