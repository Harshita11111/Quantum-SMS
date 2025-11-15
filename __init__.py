"""
liboqs package
--------------

This package provides cryptographic utilities for the
Quantum-Safe Messaging System (QSMS).

Included modules:
    - kyber_utils
    - aes_utils
    - key_exchange
    - crypto_manager
    - hash_utils
"""

# ---- Correct relative imports ----

from .kyber_utils import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)

from .aes_utils import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    derive_key_from_shared_secret,
)

from .Key_exchange import (
    PQKeyExchange,
    handshake_client,
    handshake_server,
)

from .cryptomanager import CryptoManager

from .hash_utils import (
    sha3_256_hash,
    sha3_512_hash,
    sha512_hash,
)

__all__ = [
    "generate_kyber_keypair",
    "kyber_encapsulate",
    "kyber_decapsulate",

    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "derive_key_from_shared_secret",

    "PQKeyExchange",
    "handshake_client",
    "handshake_server",

    "CryptoManager",

    "sha3_256_hash",
    "sha3_512_hash",
    "sha512_hash",
]
