# __init__.py — QSMS package public API and small integration helpers

from __future__ import annotations

# Re-export core modules / classes
from .aes_utils import (
    generate_aes_key,
    derive_key_from_shared_secret,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from .kyber_utils import (
    PROTOCOL_INFO,
    MAX_FRAME,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    KeySchedule,
    QSMSKeySchedule,
    send_frame,
    recv_frame,
    encrypt_gcm as pyd_crypto_encrypt_gcm,
    decrypt_gcm as pyd_crypto_decrypt_gcm,
    safe_utf8_decode,
)
from .crypto_manager import CryptoManager

__all__ = [
    # aes_utils
    "generate_aes_key",
    "derive_key_from_shared_secret",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    # kyber_utils
    "PROTOCOL_INFO",
    "MAX_FRAME",
    "GCM_NONCE_BYTES",
    "GCM_TAG_BYTES",
    "KeySchedule",
    "QSMSKeySchedule",
    "send_frame",
    "recv_frame",
    "pyd_crypto_encrypt_gcm",
    "pyd_crypto_decrypt_gcm",
    "safe_utf8_decode",
    # crypto_manager
    "CryptoManager",
]

# Convenience helper to derive the AES key exactly as KeySchedule expects.
def derive_aes_key_from_handshake(public_key: bytes, ct: bytes, shared_secret: bytes,
                                  *, info: bytes = b"qsms-aes-key", length: int = 32) -> (bytes, KeySchedule):
    """
    Derive an AES key using the same salt and AAD computed by QSMSKeySchedule.

    Returns (derived_key, KeySchedule). The derived_key uses aes_utils.derive_key_from_shared_secret
    with salt = SHA256(public_key || ct) (the same salt used in QSMSKeySchedule).
    """
    ks = QSMSKeySchedule.derive(public_key, ct, shared_secret)
    # Use the canonical derive function from aes_utils with the same salt to ensure agreement.
    dk = derive_key_from_shared_secret(shared_secret, salt=ks.salt, info=info, length=length)
    return dk, ks
