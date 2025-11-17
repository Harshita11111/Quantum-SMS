"""
aes_utils.py

Utility functions for AES authenticated encryption using AES-GCM,
and key derivation from a shared secret using HKDF (SHA-256).

Designed for use inside the QSMS project (hybrid Kyber + AES model).

Requirements:
    pip install cryptography

API:
    - generate_aes_key(key_size=32) -> bytes
    - derive_key_from_shared_secret(shared_secret, *, salt=None, info=None, length=32) -> bytes
    - encrypt_aes_gcm(plaintext, key, associated_data=None, nonce=None) -> Dict[str, bytes]
        returns {'nonce': bytes, 'ciphertext': bytes} where ciphertext already includes the tag
    - decrypt_aes_gcm(nonce, ciphertext, key, associated_data=None) -> bytes

Security notes (important for QSMS):
    • Never reuse a nonce with the same key. This module generates a fresh 12-byte
      random nonce by default.
    • For key derivation, pass a non-secret, per-session HKDF salt. In QSMS we use:
        salt = SHA256(server_public_key || kem_ciphertext)
      and we typically use the same value as AES-GCM AAD to bind app data to the
      exact handshake transcript.
"""

from __future__ import annotations

import os
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ========= Constants =========

DEFAULT_KEY_SIZE: int = 32      # 32 bytes == AES-256
NONCE_SIZE: int = 12            # 96-bit nonce (recommended for GCM)


# ========= Helpers =========

def _is_bytes_like(x) -> bool:
    return isinstance(x, (bytes, bytearray, memoryview))


# ========= Public API =========

def generate_aes_key(key_size: int = DEFAULT_KEY_SIZE) -> bytes:
    """
    Generate a cryptographically secure random AES key.

    Args:
        key_size: length in bytes (16, 24, or 32). Default 32 (AES-256).

    Returns:
        Random key bytes.
    """
    if key_size not in (16, 24, 32):
        raise ValueError("Invalid AES key size. Use 16, 24, or 32 bytes.")
    return os.urandom(key_size)


def derive_key_from_shared_secret(
    shared_secret: bytes,
    *,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None,
    length: int = DEFAULT_KEY_SIZE,
) -> bytes:
    """
    Derive a symmetric key from a shared secret using HKDF-SHA256.

    Typical QSMS usage (recommended):
        salt = SHA256(server_public_key || kem_ciphertext)
        info = b"qsms-aes-key"  # protocol label / context
        length = 32              # AES-256

    Args:
        shared_secret: raw shared secret bytes (e.g., from Kyber KEM).
        salt: optional HKDF salt (public, per-session). If None, HKDF uses zeros.
        info: optional context/application-specific info (bytes).
        length: resulting key length in bytes (16/24/32).

    Returns:
        Derived key bytes of requested length.
    """
    if not _is_bytes_like(shared_secret):
        raise TypeError("shared_secret must be bytes-like")
    if salt is not None and not _is_bytes_like(salt):
        raise TypeError("salt must be bytes-like or None")
    if info is not None and not _is_bytes_like(info):
        raise TypeError("info must be bytes-like or None")
    if length not in (16, 24, 32):
        raise ValueError("Derived key length must be 16, 24, or 32 bytes.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=bytes(salt) if salt is not None else None,
        info=bytes(info) if info is not None else None,
    )
    return hkdf.derive(bytes(shared_secret))


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    *,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Dict[str, bytes]:
    """
    Encrypt plaintext using AES-GCM.

    Args:
        plaintext: bytes to encrypt.
        key: AES key (16/24/32 bytes).
        associated_data: optional AAD (bytes). Must match at decryption.
        nonce: optional 12-byte nonce. If omitted, a fresh random nonce is used.

    Returns:
        {'nonce': <12 bytes>, 'ciphertext': <ciphertext||tag>}

    Notes:
        • Never reuse a (key, nonce) pair.
        • AAD is authenticated but not encrypted; use it to bind app data to the handshake.
    """
    if not _is_bytes_like(plaintext):
        raise TypeError("plaintext must be bytes-like")
    if not _is_bytes_like(key):
        raise TypeError("key must be bytes-like")
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    if associated_data is not None and not _is_bytes_like(associated_data):
        raise TypeError("associated_data must be bytes-like or None")

    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    else:
        if not _is_bytes_like(nonce):
            raise TypeError("nonce must be bytes-like or None")
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes long")

    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(
        bytes(nonce),
        bytes(plaintext),
        bytes(associated_data) if associated_data is not None else None,
    )
    return {"nonce": bytes(nonce), "ciphertext": ciphertext}


def decrypt_aes_gcm(
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
    *,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt AES-GCM ciphertext.

    Args:
        nonce: 12-byte nonce used at encryption.
        ciphertext: bytes as returned by AESGCM.encrypt (ciphertext||tag).
        key: AES key (16/24/32 bytes).
        associated_data: optional AAD (must match encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if authentication fails (wrong key/AAD/nonce or tampering).
    """
    if not _is_bytes_like(nonce):
        raise TypeError("nonce must be bytes-like")
    if not _is_bytes_like(ciphertext):
        raise TypeError("ciphertext must be bytes-like")
    if not _is_bytes_like(key):
        raise TypeError("key must be bytes-like")
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes long")
    if associated_data is not None and not _is_bytes_like(associated_data):
        raise TypeError("associated_data must be bytes-like or None")

    aesgcm = AESGCM(bytes(key))
    plaintext = aesgcm.decrypt(
        bytes(nonce),
        bytes(ciphertext),
        bytes(associated_data) if associated_data is not None else None,
    )
    return plaintext


# ========= Exports =========

__all__ = [
    "DEFAULT_KEY_SIZE",
    "NONCE_SIZE",
    "generate_aes_key",
    "derive_key_from_shared_secret",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
]


# ========= Self-test =========

if __name__ == "__main__":
    from base64 import b64encode

    print("[aes_utils] Running self-test...")
    # Simulate a shared secret (e.g., from Kyber decapsulation)
    shared_secret = os.urandom(32)

    # In QSMS, pass a real salt like SHA256(pk||ct). Here we just demo a constant label in info.
    key = derive_key_from_shared_secret(shared_secret, info=b"qsms-aes-key")
    print(f"Derived key (b64): {b64encode(key).decode()}")

    message = b"Hello QSMS \xe2\x80\x94 this is a test message!"
    aad = b"demo-handshake-binding"

    enc = encrypt_aes_gcm(message, key, associated_data=aad)
    print(f"Nonce (b64): {b64encode(enc['nonce']).decode()}")
    print(f"Ciphertext+Tag (b64): {b64encode(enc['ciphertext']).decode()}")

    dec = decrypt_aes_gcm(enc["nonce"], enc["ciphertext"], key, associated_data=aad)
    assert dec == message, "Decrypted message does not match original!"
    print("[aes_utils] Self-test passed.")
