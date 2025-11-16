
"""aes_utils.py

Utility functions for AES authenticated encryption using AES-GCM,
and key derivation from a shared secret using HKDF (SHA-256).

Designed for use inside the QSMS project (hybrid Kyber + AES model).

Requirements:
    pip install cryptography

API:
    - generate_aes_key(key_size=32) -> bytes
    - derive_key_from_shared_secret(shared_secret: bytes, salt: Optional[bytes]=None, info: Optional[bytes]=None, length: int=32) -> bytes
    - encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: Optional[bytes]=None) -> dict
        returns { 'nonce': bytes, 'ciphertext': bytes } where ciphertext already includes the tag
    - decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: Optional[bytes]=None) -> bytes

Includes a small self-test when run as __main__.
"""
from __future__ import annotations          #This line makes Python treat type hints as strings (not as actual evaluated objects at runtime).

import os
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Constants
DEFAULT_KEY_SIZE = 32  # 32 bytes == 256-bit AES key
NONCE_SIZE = 12  # 96-bit nonce recommended for GCM


def generate_aes_key(key_size: int = DEFAULT_KEY_SIZE) -> bytes:
    """Generate a cryptographically secure random AES key.

    Args:
        key_size: length in bytes (16, 24, or 32). Default 32 (AES-256).

    Returns:
        bytes: random key.
    """
    if key_size not in (16, 24, 32):
        raise ValueError("Invalid AES key size. Use 16, 24 or 32 bytes.")
    return os.urandom(key_size)


def derive_key_from_shared_secret(
    shared_secret: bytes,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None,
    length: int = DEFAULT_KEY_SIZE,
) -> bytes:
    """Derive a symmetric AES key from a shared secret using HKDF-SHA256.

    Typically used after Kyber KEM decapsulation to derive AES key material.

    Args:
        shared_secret: raw shared secret bytes from KEM.
        salt: optional salt (if None, HKDF uses zeros).
        info: optional context/application-specific info.
        length: length in bytes to derive (16/24/32).

    Returns:
        bytes: derived key of requested length.
    """
    if length not in (16, 24, 32):
        raise ValueError("Derived key length must be 16, 24, or 32 bytes.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Dict[str, bytes]:
    """Encrypt plaintext using AES-GCM.

    Args:
        plaintext: bytes to encrypt.
        key: AES key (16/24/32 bytes).
        associated_data: optional additional authenticated data (AAD).
        nonce: optional 12-byte nonce. If omitted, a secure random nonce is generated.

    Returns:
        dict with keys:
            'nonce' (bytes) - the nonce used (must be provided to the decryptor)
            'ciphertext' (bytes) - ciphertext concatenated with GCM tag
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes long")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt_aes_gcm(
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt AES-GCM ciphertext.

    Args:
        nonce: 12-byte nonce used during encryption.
        ciphertext: ciphertext bytes as returned by AESGCM.encrypt (ciphertext||tag).
        key: AES key.
        associated_data: optional AAD bytes used during encryption.

    Returns:
        plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if authentication fails.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes long")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext


# Simple self-test (not a substitute for unit tests)
if __name__ == "__main__":
    from base64 import b64encode, b64decode

    print("Running aes_utils self-test...")
    # Simulate a shared secret (e.g., from Kyber decapsulation)
    shared_secret = os.urandom(32)
    key = derive_key_from_shared_secret(shared_secret, info=b"qsms-aes-key")
    print(f"Derived key (base64): {b64encode(key).decode()}")

    message = "Hello QSMS — this is a test message!".encode("utf-8")

    aad = b"chat:12345:user:alice->bob"

    encrypted = encrypt_aes_gcm(message, key, associated_data=aad)
    print(f"Nonce (b64): {b64encode(encrypted['nonce']).decode()}")
    print(f"Ciphertext+Tag (b64): {b64encode(encrypted['ciphertext']).decode()}")

    decrypted = decrypt_aes_gcm(encrypted['nonce'], encrypted['ciphertext'], key, associated_data=aad)
    assert decrypted == message, "Decrypted message does not match original"
    print("Self-test passed — plaintext successfully recovered.")
