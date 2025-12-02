# Backend/key_storage_service.py
# Role: CRUD helpers for storing and retrieving user keypairs (public/private) and AES session keys.
# Important functions

# create_keypair_for_user(db, user_id) — uses generate_kyber_keypair() to produce pk, sk and store them in KeyStorage.

# get_public_key_for_user(db, user_id) / get_private_key_for_user(...)

# ensure_keypair_for_user(user_id) — creates one if missing

from typing import Optional, Tuple
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import KeyStorage
from .kyber_utils import generate_kyber_keypair

def _get_session(maybe_db: Optional[Session]):
    if maybe_db is not None:
        return maybe_db, False
    return SessionLocal(), True

def create_keypair_for_user(db: Session, user_id: int) -> KeyStorage:
    """
    Create and persist a Kyber keypair for user.
    Expects an active DB session (db).
    Returns the created KeyStorage record.
    """
    pk, sk = generate_kyber_keypair()  # MUST return bytes (pk, sk)
    rec = KeyStorage(user_id=user_id, public_key=pk, private_key=sk)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec

def ensure_keypair_for_user(user_id: int) -> KeyStorage:
    """
    Ensure a keypair exists for user_id. Returns KeyStorage record.
    Uses an internal session.
    """
    db, close = _get_session(None)
    try:
        rec = db.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
        if rec:
            return rec
        return create_keypair_for_user(db, user_id)
    finally:
        if close:
            db.close()

def get_public_key_for_user(db: Optional[Session], user_id: int) -> Optional[bytes]:
    """
    If db is provided, use it; otherwise uses a new session.
    Returns bytes or None.
    """
    sess, close = _get_session(db)
    try:
        rec = sess.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
        if not rec:
            return None
        return rec.public_key
    finally:
        if close:
            sess.close()

def get_private_key_for_user(db: Optional[Session], user_id: int) -> Optional[bytes]:
    sess, close = _get_session(db)
    try:
        rec = sess.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
        if not rec:
            return None
        return rec.private_key
    finally:
        if close:
            sess.close()

def store_aes_key_for_user(db: Optional[Session], user_id: int, aes_key: bytes):
    sess, close = _get_session(db)
    try:
        rec = sess.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
        if not rec:
            return None
        rec.aes_session_key = aes_key
        sess.commit()
        sess.refresh(rec)
        return rec
    finally:
        if close:
            sess.close()
