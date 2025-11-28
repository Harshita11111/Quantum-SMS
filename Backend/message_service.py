# message_service.py
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Message
from .crypto_manager import CryptoManager
from .key_storage_service import get_public_key_for_user

def send_message(sender_id: int, receiver_id: int, plaintext: bytes):
    """
    Performs hybrid encryption (Kyber KEM to encapsulate symmetric AES key,
    AES-GCM to encrypt message). Stores message record with kem_ct + ciphertext + nonce.
    """
    db: Session = SessionLocal()
    try:
        # fetch receiver public key
        pk = get_public_key_for_user(db, receiver_id)
        if pk is None:
            raise ValueError("Receiver public key not found")

        cm = CryptoManager()
        # encapsulate and encrypt in one convenience call
        result = cm.encrypt_for_recipient(pk, plaintext)
        # result: {'kem_ct': bytes, 'nonce': bytes, 'ciphertext': bytes}

        msg = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            kem_ct=result["kem_ct"],
            nonce=result["nonce"],
            ciphertext=result["ciphertext"]
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


def get_messages_for_user(user_id: int):
    db: Session = SessionLocal()
    try:
        rows = db.query(Message).filter(Message.receiver_id == user_id).order_by(Message.created_at).all()
        return rows
    finally:
        db.close()
