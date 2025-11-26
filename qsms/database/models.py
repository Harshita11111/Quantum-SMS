# qsms/database/models.py
from __future__ import annotations

from sqlalchemy import (
    Column, Integer, String, LargeBinary, DateTime, ForeignKey, Boolean, func
)
from sqlalchemy.orm import declarative_base, relationship, synonym

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)

    # canonical column names
    password_hash_b64 = Column(String(512), nullable=False)
    salt_b64 = Column(String(256), nullable=False)
    pbkdf2_iter = Column(Integer, nullable=False, default=200_000)

    # legacy/alt attribute names used by store code
    pw_hash = synonym("password_hash_b64")   # <-- lets kwargs 'pw_hash=...' work
    salt = synonym("salt_b64")               # <-- lets kwargs 'salt=...' work

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    last_login_at = Column(DateTime, nullable=True)

    keys = relationship("Key", back_populates="user", cascade="all, delete-orphan")
    auth_audits = relationship(
        "AuthAudit", back_populates="user", cascade="all, delete-orphan"
    )

class AuthAudit(Base):
    __tablename__ = "auth_audit"

    id = Column(Integer, primary_key=True)

    # keep FK but make it optional (record_login may not look up the user id)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)

    # <-- add this so kwargs with username work
    username = Column(String(64), nullable=False, index=True)

    ip = Column(String(45), nullable=True)
    ok = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    user = relationship("User", back_populates="auth_audits")


class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(String(32), nullable=False, index=True)
    device_id = Column(String(128), nullable=True, index=True)
    public_key = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    user = relationship("User", back_populates="keys")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    sender = Column(String(64), nullable=False, index=True)
    recipient = Column(String(64), nullable=False, index=True)
    nonce = Column(LargeBinary, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    aad = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    delivered_at = Column(DateTime, nullable=True)

def create_all(engine):
    Base.metadata.create_all(engine)
