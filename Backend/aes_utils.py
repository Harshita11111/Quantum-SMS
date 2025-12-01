# aes_utils.py
# Simple explanation:

# derive_key_from_shared_secret uses HKDF-SHA256 to get an AES key from the KEM shared secret.

# Encryption uses AES-GCM (authenticated encryption): returns nonce and ciphertext (ciphertext includes tag).

# Decryption verifies the tag and returns plaintext.

import os
from typing import Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12  # 96 bits recommended for GCM
DEFAULT_KEY_SIZE = 32  # bytes -> AES-256

def derive_key_from_shared_secret(shared_secret: bytes, salt: Optional[bytes] = None, info: Optional[bytes] = None, length: int = DEFAULT_KEY_SIZE) -> bytes:
    if length not in (16, 24, 32):
        raise ValueError("length must be 16/24/32")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)

def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None, nonce: Optional[bytes] = None) -> Dict[str, bytes]:
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return {"nonce": nonce, "ciphertext": ciphertext}

def decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
