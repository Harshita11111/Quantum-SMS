# qsms/database/message_storage.py
"""
Persistence helpers for encrypted chat messages.

- Stores ONLY encrypted payloads: (nonce, ciphertext, optional AAD).
- Uses usernames for sender/recipient (matches current project code).
- Deterministic ordering: whenever we sort by created_at we also tie-break on id.
- Uses SQLAlchemy 2.x style Session.get() (no deprecated Query.get()).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from .db_config import session_scope
from .models import Message


# ---------------------------------------------------------------------------
# Create / Update
# ---------------------------------------------------------------------------

def save_message(
    sender: str,
    recipient: str,
    nonce: bytes,
    ciphertext: bytes,
    aad: Optional[bytes] = None,
) -> int:
    """Insert an encrypted message row and return its id."""
    with session_scope() as s:
        row = Message(
            sender=sender,
            recipient=recipient,
            nonce=nonce,
            ciphertext=ciphertext,
            aad=aad,
        )
        s.add(row)
        s.flush()  # get PK before committing
        return row.id


def mark_delivered(message_id: int, ts: Optional[datetime] = None) -> bool:
    """Set delivered_at for a message. Returns True if updated."""
    with session_scope() as s:
        row = s.get(Message, message_id)  # SQLAlchemy 2.x
        if not row:
            return False
        row.delivered_at = ts or datetime.utcnow()
        return True


def delete_message(message_id: int) -> bool:
    """Hard-delete a single message. Returns True if deleted."""
    with session_scope() as s:
        row = s.get(Message, message_id)  # SQLAlchemy 2.x
        if not row:
            return False
        s.delete(row)
        return True


def purge_user(username: str) -> int:
    """
    Delete all messages where the user participates (sender or recipient).
    Returns number of rows deleted.
    """
    with session_scope() as s:
        q = s.query(Message).filter(
            (Message.sender == username) | (Message.recipient == username)
        )
        count = q.count()
        q.delete(synchronize_session=False)
        return count


# ---------------------------------------------------------------------------
# Read / Query
# ---------------------------------------------------------------------------

def fetch_inbox(
    username: str,
    *,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    include_delivered: bool = True,
    limit: int = 100,
    offset: int = 0,
    newest_first: bool = True,
) -> List[Message]:
    """
    Get messages addressed to `username`.
    Deterministic order: created_at + id.
    """
    with session_scope() as s:
        q = s.query(Message).filter(Message.recipient == username)

        if since is not None:
            q = q.filter(Message.created_at >= since)
        if until is not None:
            q = q.filter(Message.created_at <= until)
        if not include_delivered:
            q = q.filter(Message.delivered_at.is_(None))

        if newest_first:
            q = q.order_by(Message.created_at.desc(), Message.id.desc())
        else:
            q = q.order_by(Message.created_at.asc(), Message.id.asc())

        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)

        return q.all()


def count_unread(recipient: str) -> int:
    """Number of messages for `recipient` that are not yet marked delivered."""
    with session_scope() as s:
        return (
            s.query(Message)
            .filter(Message.recipient == recipient, Message.delivered_at.is_(None))
            .count()
        )


def fetch_conversation(
    user_a: str,
    user_b: str,
    *,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 200,
    offset: int = 0,
    chronological: bool = True,
) -> List[Message]:
    """
    Conversation history between user_a and user_b (both directions).
    Deterministic order: created_at + id.
    """
    with session_scope() as s:
        q = s.query(Message).filter(
            ((Message.sender == user_a) & (Message.recipient == user_b))
            | ((Message.sender == user_b) & (Message.recipient == user_a))
        )

        if since is not None:
            q = q.filter(Message.created_at >= since)
        if until is not None:
            q = q.filter(Message.created_at <= until)

        if chronological:
            q = q.order_by(Message.created_at.asc(), Message.id.asc())
        else:
            q = q.order_by(Message.created_at.desc(), Message.id.desc())

        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)

        return q.all()


def fetch_outbox(
    username: str,
    *,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
    newest_first: bool = True,
) -> List[Message]:
    """
    Messages sent by `username`.
    Deterministic order: created_at + id.
    """
    with session_scope() as s:
        q = s.query(Message).filter(Message.sender == username)

        if since is not None:
            q = q.filter(Message.created_at >= since)
        if until is not None:
            q = q.filter(Message.created_at <= until)

        if newest_first:
            q = q.order_by(Message.created_at.desc(), Message.id.desc())
        else:
            q = q.order_by(Message.created_at.asc(), Message.id.asc())

        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)

        return q.all()
