# qsms/database/key_storage.py
from __future__ import annotations

from typing import List, Optional

from .db_config import session_scope
from .models import Key


def save_public_key(
    username: str,
    public_key: bytes,
    *,
    key_type: str = "kyber-pk",
    device_id: Optional[str] = None,
    replace: bool = False,  # default: don't replace; keep history unless requested
) -> int:
    """
    Insert (or optionally replace) a user's public key row and return its id.

    For ephemeral/rotating materials like wrapped session keys ("aes-wrap"),
    we always append and never replace (history is expected by tests/consumers).
    """
    # Local import to avoid circulars
    from .models import User

    # Never replace wrapped session keys – maintain append-only history
    if key_type == "aes-wrap":
        replace = False

    with session_scope() as s:
        # Resolve the user_id
        u = s.query(User).filter_by(username=username).one_or_none()
        if not u:
            raise ValueError(f"cannot store key: user '{username}' does not exist")

        if replace:
            row = (
                s.query(Key)
                .filter_by(user_id=u.id, type=key_type, device_id=device_id)
                .one_or_none()
            )
            if row:
                row.public_key = public_key
                s.flush()
                return row.id

        row = Key(
            user_id=u.id,
            type=key_type,
            public_key=public_key,
            device_id=device_id,
        )
        s.add(row)
        s.flush()
        return row.id


def get_public_keys(
    username: str,
    *,
    key_type: str = "kyber-pk",
    device_id: Optional[str] = None,
    newest_first: bool = True,
) -> List[Key]:
    """Fetch public keys for a user (optionally by device and type)."""
    from .models import User

    with session_scope() as s:
        u = s.query(User).filter_by(username=username).one_or_none()
        if not u:
            return []
        q = s.query(Key).filter_by(user_id=u.id, type=key_type)
        if device_id is not None:
            q = q.filter_by(device_id=device_id)
        # Deterministic ordering (tie-break on id)
        if newest_first:
            q = q.order_by(Key.created_at.desc(), Key.id.desc())
        else:
            q = q.order_by(Key.created_at.asc(), Key.id.asc())
        return q.all()


def get_latest_public_key(
    username: str,
    *,
    key_type: str = "kyber-pk",
    device_id: Optional[str] = None,
) -> Optional[bytes]:
    """Return newest public key bytes or None."""
    rows = get_public_keys(
        username, key_type=key_type, device_id=device_id, newest_first=True
    )
    return rows[0].public_key if rows else None


def save_wrapped_session_key(
    username: str,
    wrapped_key: bytes,
    *,
    device_id: Optional[str] = None,
    label: str = "aes-wrap",
    replace: bool = False,  # force append-only behavior for wrapped keys
) -> int:
    """
    Persist a wrapped (encrypted) symmetric key. We reuse the keys table with
    a different type label (default 'aes-wrap'). Wrapped keys are append-only.
    """
    return save_public_key(
        username=username,
        public_key=wrapped_key,
        key_type=label,
        device_id=device_id,
        replace=False,  # ignore caller's value to guarantee append-only
    )


def get_wrapped_session_keys(
    username: str,
    *,
    device_id: Optional[str] = None,
    label: str = "aes-wrap",
    newest_first: bool = True,
) -> List[bytes]:
    """Fetch wrapped symmetric keys (ciphertext blobs) for a user."""
    rows = get_public_keys(
        username, key_type=label, device_id=device_id, newest_first=newest_first
    )
    return [r.public_key for r in rows]


def get_latest_wrapped_session_key(
    username: str,
    *,
    device_id: Optional[str] = None,
    label: str = "aes-wrap",
) -> Optional[bytes]:
    """Return newest wrapped symmetric key for a user (or None)."""
    rows = get_public_keys(
        username, key_type=label, device_id=device_id, newest_first=True
    )
    return rows[0].public_key if rows else None
