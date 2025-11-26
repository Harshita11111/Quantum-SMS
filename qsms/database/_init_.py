"""
qsms.database

Database configuration and ORM models for the Quantum-Safe Messaging (QSMS) project.

Re-exports:
    - Engine/Session helpers: get_engine, get_session, session_scope, DATABASE_URL
    - ORM base & models: Base, User, Session, Key, Message, AuthAudit
    - Schema bootstrap: create_all()
"""

from __future__ import annotations

# ---- Config helpers (singleton engine + sessions) -------------------------
from .db_config import (
    DATABASE_URL,
    get_engine,
    get_session,
    session_scope,
)

# ---- ORM base & models ----------------------------------------------------
from .models import (
    Base,
    User,
    Session,
    Key,
    Message,
    AuthAudit,
    create_all,
)

__all__ = [
    # Config
    "DATABASE_URL",
    "get_engine",
    "get_session",
    "session_scope",
    # Models / schema
    "Base",
    "User",
    "Session",
    "Key",
    "Message",
    "AuthAudit",
    "create_all",
]

# Optional package version tag
__version__ = "0.1.0"
