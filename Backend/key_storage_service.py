# key_storage_service.py
from sqlalchemy.orm import Session
from .models import KeyStorage
from .kyber_utils import generate_kyber_keypair

def create_keypair_for_user(db: Session, user_id: int):
    """
    Create and persist a Kyber keypair for user.
    Expects an active DB session (db).
    """
    # generate keys (public, private)
    pk, sk = generate_kyber_keypair()
    rec = KeyStorage(user_id=user_id, public_key=pk, private_key=sk)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec

def get_public_key_for_user(db: Session, user_id: int):
    rec = db.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
    if not rec:
        return None
    return rec.public_key

def get_private_key_for_user(db: Session, user_id: int):
    rec = db.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
    if not rec:
        return None
    return rec.private_key

def store_aes_key_for_user(db: Session, user_id: int, aes_key: bytes):
    rec = db.query(KeyStorage).filter(KeyStorage.user_id == user_id).first()
    if not rec:
        return None
    rec.aes_session_key = aes_key
    db.commit()
    db.refresh(rec)
    return rec
