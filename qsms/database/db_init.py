"""
qsms.database.db_init

Schema initializer & small CLI for the QSMS database.

Usage (from project root):
    # Create tables if they don't exist
    python -m qsms.database.db_init

    # Recreate schema (DROPS ALL TABLES, then creates)
    python -m qsms.database.db_init --recreate

    # Seed a demo user (only if not present)
    python -m qsms.database.db_init --seed alice "correct horse battery staple"
"""

from __future__ import annotations

import os
import sys
import argparse
import base64
import os
from hashlib import pbkdf2_hmac
from typing import Optional

from .db_config import get_engine, session_scope, DATABASE_URL  # engine/session helpers
from .models import Base, create_all, User  # ORM models & Base

# ---------- helpers ----------

def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

def _ensure_user(username: str, password: str, *, iterations: int = 200_000) -> bool:
    """
    Insert a user if it doesn't exist. Returns True if created, False if already present.
    """
    with session_scope() as s:
        existing = s.query(User).filter_by(username=username).one_or_none()
        if existing:
            return False
        salt = os.urandom(16)
        pw_hash = _pbkdf2(password, salt, iterations)
        s.add(User(username=username, pw_hash=pw_hash, salt=salt, pbkdf2_iter=iterations))
        return True

# ---------- CLI ----------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize or recreate the QSMS database schema."
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="DROP ALL TABLES then create them again (DANGEROUS).",
    )
    parser.add_argument(
        "--seed",
        nargs=2,
        metavar=("USERNAME", "PASSWORD"),
        help="Create a demo user if it does not exist.",
    )
    args = parser.parse_args(argv)

    # Build engine (respects DATABASE_URL env var)
    engine = get_engine()

    if args.recreate:
        print("[!] Dropping all tables …")
        Base.metadata.drop_all(engine)   # uses models.Base
        print("[+] Creating schema …")
        create_all(engine)               # uses models.create_all
    else:
        print("[+] Creating schema if needed …")
        create_all(engine)

    if args.seed:
        username, password = args.seed
        created = _ensure_user(username, password)
        if created:
            print(f"[+] Seeded user: {username}")
        else:
            print(f"[i] User already exists: {username}")

    print(f"[✓] DB ready at {DATABASE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from .db_config import engine
print("Using DB:", engine.url)