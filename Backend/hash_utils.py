# hash_utils.py
# Simple explanation: Utility functions for hashing where needed. (Not for password storage — werkzeug is used for that.)

import hashlib

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
