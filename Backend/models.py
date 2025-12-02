# models.py

# Simple explanation: Each class maps to a DB table. KeyStorage stores a user's public/private keys. Message stores hybrid-encrypted messages (KEM ciphertext + AES-GCM ciphertext).

from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    keys = relationship("KeyStorage", back_populates="user")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")


class KeyStorage(Base):
    __tablename__ = "keystorage"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    private_key = Column(LargeBinary, nullable=False)
    aes_session_key = Column(LargeBinary, nullable=True)   # optional, store encrypted if needed
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="keys")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)   # AES-GCM ciphertext (includes tag)
    nonce = Column(LargeBinary, nullable=False)        # AES-GCM nonce
    kem_ct = Column(LargeBinary, nullable=False)       # Kyber encapsulation ciphertext (encrypted key)
    created_at = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")
