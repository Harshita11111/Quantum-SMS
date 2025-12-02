"""
pqc_key_exchange.py
--------------------
Handles the Hybrid Post-Quantum Key Exchange using:

✓ Kyber512 (Post-Quantum KEM — from liboqs)
✓ HKDF-SHA256 (Key derivation)
✓ AES-256-GCM (Symmetric encryption for data)

Used by both:
   - Server (decapsulation)
   - Client (encapsulation)

This module acts as the low-level handshake module.
"""

from __future__ import annotations
import oqs
from aes_utils import derive_key_from_shared_secret


class PQCKeyExchange:
    """
    PQC Key Exchange Manager (Kyber512).
    
    Provides:
        ▸ generate_keypair()  — Receiver uses this
        ▸ encapsulate()      — Sender uses this
        ▸ decapsulate()      — Receiver uses this
        ▸ get_shared_aes_key()
    """

    def __init__(self, algorithm: str = "Kyber512"):
        self.algorithm = algorithm
        self.server_kem = oqs.KeyEncapsulation(algorithm)  # for decapsulation
        self.sender_key = None   # AES derived key (client)
        self.receiver_key = None # AES derived key (server)

    # --------------------------------------------------------
    # 1. Receiver-side: Generate keypair
    # --------------------------------------------------------
    def generate_keypair(self) -> bytes:
        """
        Receiver (server) generates a Kyber public key.
        Private key stays inside OQS KEM instance.
        """
        print("[KEM] Generating Kyber keypair...")
        public_key = self.server_kem.generate_keypair()
        return public_key

    # --------------------------------------------------------
    # 2. Sender-side: Encapsulation
    # --------------------------------------------------------
    def encapsulate(self, receiver_public_key: bytes):
        """
        Sender uses the receiver's public key.

        Returns:
            kem_ciphertext (bytes)
            shared_secret (bytes)
        """
        print("[KEM] Encapsulation started...")

        client = oqs.KeyEncapsulation(self.algorithm)

        # Try method variations due to API differences
        for method_name in ("encap_secret", "encapsulate", "encap"):
            if hasattr(client, method_name):
                try:
                    method = getattr(client, method_name)
                    kem_ct, shared_secret = method(receiver_public_key)
                    print("[KEM] Encapsulation success.")
                except Exception:
                    continue
                break
        else:
            raise RuntimeError("liboqs does not support encapsulation method!")

        # Derive AES-256-GCM key
        self.sender_key = derive_key_from_shared_secret(
            shared_secret, info=b"qsms-aes-key"
        )
        return kem_ct, shared_secret

    # --------------------------------------------------------
    # 3. Receiver-side: Decapsulation
    # --------------------------------------------------------
    def decapsulate(self, kem_ciphertext: bytes):
        """
        Receiver uses its OQS KEM instance to decapsulate.

        Returns:
            shared_secret (bytes)
        """

        print("[KEM] Decapsulation started...")

        # Try decapsulation variations
        for method_name in ("decap_secret", "decapsulate", "decap"):
            if hasattr(self.server_kem, method_name):
                try:
                    method = getattr(self.server_kem, method_name)
                    shared_secret = method(kem_ciphertext)
                    print("[KEM] Decapsulation success.")
                except Exception:
                    continue
                break
        else:
            raise RuntimeError("liboqs does not support decapsulation method!")

        # Derive AES key
        self.receiver_key = derive_key_from_shared_secret(
            shared_secret, info=b"qsms-aes-key"
        )
        return shared_secret

    # --------------------------------------------------------
    # 4. Retrieve AES-256 key after handshake
    # --------------------------------------------------------
    def get_sender_aes_key(self) -> bytes:
        if not self.sender_key:
            raise ValueError("Sender AES key not initialized")
        return self.sender_key

    def get_receiver_aes_key(self) -> bytes:
        if not self.receiver_key:
            raise ValueError("Receiver AES key not initialized")
        return self.receiver_key


# ------------------------------------------------------------
#        SELF TEST — KEM Handshake Check
# ------------------------------------------------------------
if __name__ == "__main__":
    print("[TEST] Starting PQC Key Exchange Self-Test...\n")

    pqc = PQCKeyExchange()

    # Server creates keypair
    pk = pqc.generate_keypair()

    # Client encapsulates
    kem_ct, ss1 = pqc.encapsulate(pk)

    # Server decapsulates
    ss2 = pqc.decapsulate(kem_ct)

    print("\nShared Secret (Client):", ss1.hex())
    print("Shared Secret (Server):", ss2.hex())
    print("\nMatch?", ss1 == ss2)

    if ss1 == ss2:
        print("\n[TEST PASSED] PQC Key Exchange working correctly.")
    else:
        print("\n[TEST FAILED] Shared secrets do not match!")
