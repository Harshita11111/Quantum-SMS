# Backend/message_service.py
# Role: High-level message handling: encrypt a message for a receiver and persist it; fetch and decrypt messages for a user.
"""Simple explanation: Implements offline message delivery: the sender stores an encrypted blob; when the receiver comes online they can fetch and decrypt messages with their private key."""
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Message
from .crypto_manager import CryptoManager
from .key_storage_service import get_public_key_for_user, get_private_key_for_user, ensure_keypair_for_user

def send_message(sender_id: int, receiver_id: int, plaintext: bytes) -> Tuple[bool, object]:
    """
    Hybrid-encrypt plaintext for receiver and store a Message record with:
      - kem_ct (bytes)
      - nonce (bytes)
      - ciphertext (bytes)
    Returns (True, message_id) on success, (False, error_str) on failure.
    """
    db: Session = SessionLocal()
    try:
        pk = get_public_key_for_user(db, receiver_id)
        if pk is None:
            # Optionally create a keypair for receiver (dev convenience)
            rec = ensure_keypair_for_user(receiver_id)
            pk = rec.public_key

        cm = CryptoManager()
        # convenience method must return raw bytes
        result = cm.encrypt_for_recipient(pk, plaintext)
        kem_ct = result["kem_ct"]
        nonce = result["nonce"]
        ciphertext = result["ciphertext"]

        msg = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            kem_ct=kem_ct,
            nonce=nonce,
            ciphertext=ciphertext
        )
        db.add(msg)
        db.commit()
        db.refresh(msg)
        return True, msg.id
    except Exception as e:
        db.rollback()
        return False, str(e)
    finally:
        db.close()


def get_messages_for_user(user_id: int) -> List[Message]:
    db: Session = SessionLocal()
    try:
        rows = db.query(Message).filter(Message.receiver_id == user_id).order_by(Message.created_at).all()
        return rows
    finally:
        db.close()


def retrieve_and_decrypt_for_user(user_id: int) -> List[Tuple[int, Optional[bytes]]]:
    """
    Fetch offline/encrypted messages for user_id and attempt to decrypt each
    using the user's private key. Returns list of tuples (message_id, plaintext_or_None).
    """
    db: Session = SessionLocal()
    out = []
    try:
        priv = get_private_key_for_user(db, user_id)
        if priv is None:
            raise ValueError("No private key for user")

        rows = db.query(Message).filter(Message.receiver_id == user_id).order_by(Message.created_at).all()
        cm = CryptoManager()
        for r in rows:
            try:
                # decrypt path: use cm to decapsulate then decrypt
                # If your CryptoManager supports decapsulate(priv, ct) use that; otherwise
                # call cm.decapsulate(ct) after setting cm._priv appropriately.
                # We'll try both common variants inside decrypt_for_recipient.  
                plaintext = cm.decrypt_for_recipient(priv, r.kem_ct, r.nonce, r.ciphertext)
                out.append((r.id, plaintext))
            except Exception:
                out.append((r.id, None))
        return out
    finally:
        db.close()
