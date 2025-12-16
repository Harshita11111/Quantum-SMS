"""
qsms.database.user_management

DB-backed user store for QSMS authentication.

This module provides a drop-in replacement for the in-memory UserStore used by
auth_protocol.AuthServer, exposing the same shape:

    class DBUserStore:
        def add_user(self, username: str, password: str, *, pbkdf2_iter: int = 200_000) -> None: ...
        def get(self, username: str) -> Optional[UserRecord]: ...

It also includes some convenient extras:
    - verify_credentials(username, password)
    - update_password(username, new_password, *, pbkdf2_iter=...)
    - record_login(username, ok, ip=None)

Notes
-----
- Passwords are stored as PBKDF2-HMAC-SHA256( password, salt, iterations ) with a 32-byte output.
- Salts are random 16 bytes (or larger). Hash & salt are persisted in the `users` table.
- Never store plaintext passwords.
"""

from __future__ import annotations

import os
import hmac
import base64
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from typing import Optional

from .db_config import session_scope  # transactional session helper
from .models import User, AuthAudit    # ORM models

# ---------------------------------------------------------------------------
# Data shape expected by auth_protocol.AuthServer
# ---------------------------------------------------------------------------

@dataclass
class UserRecord:
    """
    Matches the fields consumed by auth_protocol.AuthServer:
        - username
        - salt_b64
        - pbkdf2_iter
        - password_hash_b64
    """
    username: str
    salt_b64: str
    pbkdf2_iter: int
    password_hash_b64: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    # 32 bytes (256-bit) output, same as used in auth
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class DBUserStore:
    """
    Database-backed user store.

    Typical usage:
        store = DBUserStore()
        store.add_user("alice", "correct horse battery staple")
        rec = store.get("alice")  # -> UserRecord for the auth handshake
    """

    # ---- CRUD / Interface required by AuthServer ----

    def add_user(self, username: str, password: str, *, pbkdf2_iter: int = 200_000) -> None:
        """
        Create a new user with a salted PBKDF2 hash.
        Raises:
            ValueError if the username already exists.
        """
        salt = os.urandom(16)
        pw_hash = _pbkdf2(password, salt, pbkdf2_iter)

        with session_scope() as s:
            existing = s.query(User).filter_by(username=username).one_or_none()
            if existing:
                raise ValueError(f"user '{username}' already exists")
            s.add(User(
                username=username,
                pw_hash=pw_hash,
                salt=salt,
                pbkdf2_iter=pbkdf2_iter,
            ))
            # commit happens via session_scope

    def get(self, username: str) -> Optional[UserRecord]:
        """
        Fetch a user as a UserRecord compatible with auth_protocol.AuthServer.
        Returns None if not found (AuthServer will proceed with a fake challenge).
        """
        with session_scope() as s:
            u = s.query(User).filter_by(username=username).one_or_none()
            if not u:
                return None
            return UserRecord(
                username=u.username,
                salt_b64=_b64e(u.salt),
                pbkdf2_iter=int(u.pbkdf2_iter),
                password_hash_b64=_b64e(u.pw_hash),
            )

    # ---- Helpful extras (optional for your app) ----

    def verify_credentials(self, username: str, password: str) -> bool:
        """
        Check if the provided password matches the stored verifier.
        This mirrors what the server-side proof ultimately validates.
        """
        with session_scope() as s:
            u = s.query(User).filter_by(username=username).one_or_none()
            if not u:
                return False
            expected = u.pw_hash
            derived = _pbkdf2(password, u.salt, int(u.pbkdf2_iter))
            return hmac.compare_digest(expected, derived)

    def update_password(self, username: str, new_password: str, *, pbkdf2_iter: Optional[int] = None) -> bool:
        """
        Update a user's password and (optionally) iteration count.
        Returns True if updated, False if the user does not exist.
        """
        with session_scope() as s:
            u = s.query(User).filter_by(username=username).one_or_none()
            if not u:
                return False
            iters = int(pbkdf2_iter) if pbkdf2_iter is not None else int(u.pbkdf2_iter)
            salt = os.urandom(16)
            pw_hash = _pbkdf2(new_password, salt, iters)
            u.salt = salt
            u.pbkdf2_iter = iters
            u.pw_hash = pw_hash
            return True

    def record_login(self, username: str, ok: bool, ip: Optional[str] = None) -> None:
        """
        Persist an auth attempt (for rate-limiting/auditing).
        """
        with session_scope() as s:
            s.add(AuthAudit(username=username, ok=bool(ok), ip=ip))

    def delete_user(self, username: str) -> bool:
        """
        Remove a user and cascade-delete related rows (sessions/keys) via FK.
        Returns True if deleted, False if not found.
        """
        with session_scope() as s:
            u = s.query(User).filter_by(username=username).one_or_none()
            if not u:
                return False
            s.delete(u)
            return True


from .db_config import session_scope
from .models import User, AuthAudit


def list_all_users():
    """Return a list of all usernames stored in the database."""
    with session_scope() as s:
        users = s.query(User).order_by(User.id).all()
        return [u.username for u in users]


def list_successful_logins():
    """Return a list of usernames that have logged in successfully at least once."""
    with session_scope() as s:
        rows = (
            s.query(AuthAudit.username)
             .filter(AuthAudit.ok == True)
             .distinct()
             .all()
        )
        return [r.username for r in rows]


if __name__ == "__main__":
    # Small demo: print all users and all users with successful logins
    print("All users in DB:")
    for u in list_all_users():
        print(" -", u)

    print("\nUsers who have logged in successfully at least once:")
    for u in list_successful_logins():
        print(" -", u)
