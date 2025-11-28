# qsms/network/crypto_manager.py
"""
High-level cryptography manager for Quantum-Safe Messaging System.

This file is robust to small API differences between liboqs-python versions.
It uses the AES helpers from aes_utils.py:
  - derive_key_from_shared_secret(shared_secret, salt=None, info=None, length=32)
  - encrypt_aes_gcm(plaintext, key, associated_data=None, nonce=None) -> {'nonce','ciphertext'}
  - decrypt_aes_gcm(nonce, ciphertext, key, associated_data=None) -> plaintext
"""

from __future__ import annotations
from typing import Optional, Tuple

import oqs  # liboqs-python

# AES helpers
from .aes_utils import encrypt_aes_gcm, decrypt_aes_gcm, derive_key_from_shared_secret


class CryptoManager:
    def __init__(self, algorithm: str = "Kyber512", role: str = "unset"):
        self.algorithm = algorithm

        # liboqs KEM object (server side keeps the long-term secret)
        self.kem = oqs.KeyEncapsulation(self.algorithm)

        self.public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None
        self.role = role

        # -----------------------------
        # FIX: Provide a stable AAD API
        # -----------------------------
        # Both the client and server now have a defined "Additional Authenticated Data".
        # Must be identical on both ends for AES-GCM authentication.
        self.aad: bytes = b"qsms-auth"      # <--- FIX ADDED HERE
        # -----------------------------

    # ---------------- Key generation (server) ----------------
    def generate_keys(self) -> bytes:
        """
        Generate a keypair and return the public key bytes.
        """
        if hasattr(self.kem, "generate_keypair"):
            pk = self.kem.generate_keypair()
        else:
            gen = getattr(oqs, "generate_keypair", None)
            if gen is not None:
                pk, _sk = gen(self.algorithm)
            else:
                raise RuntimeError("No generate_keypair method found in oqs binding")
        self.public_key = pk
        return pk

    # ---------------- Encapsulation (client) ----------------
    def encapsulate(self, receiver_public_key: bytes) -> Tuple[bytes, bytes]:
        client_kem = oqs.KeyEncapsulation(self.algorithm)

        method_candidates = (
            "encap_secret", "encapsulate", "encap", "encapsulate_secret"
        )
        for name in method_candidates:
            if hasattr(client_kem, name):
                method = getattr(client_kem, name)
                try:
                    ct, ss = method(receiver_public_key)
                    self.shared_secret = ss
                    self.aes_key = derive_key_from_shared_secret(
                        ss, info=b"qsms-aes-key"
                    )
                    return ct, ss
                except TypeError:
                    continue

        # fallback
        ct, ss = client_kem.encapsulate(receiver_public_key)
        self.shared_secret = ss
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
        return ct, ss

    # ---------------- Decapsulation (server) ----------------
    def decapsulate(self, kem_ciphertext: bytes) -> bytes:
        decap_candidates = (
            "decapsulate", "decap_secret", "decap", "decapsulate_secret"
        )
        for name in decap_candidates:
            if hasattr(self.kem, name):
                method = getattr(self.kem, name)
                try:
                    ss = method(kem_ciphertext)
                    self.shared_secret = ss
                    self.aes_key = derive_key_from_shared_secret(
                        ss, info=b"qsms-aes-key"
                    )
                    return ss
                except TypeError:
                    # maybe requires secret key export
                    try:
                        if hasattr(self.kem, "export_secret_key"):
                            sk = self.kem.export_secret_key()
                            ss = method(kem_ciphertext, sk)
                            self.shared_secret = ss
                            self.aes_key = derive_key_from_shared_secret(
                                ss, info=b"qsms-aes-key"
                            )
                            return ss
                    except Exception:
                        pass
                    continue

        # generic fallback
        ss = self.kem.decapsulate(kem_ciphertext)
        self.shared_secret = ss
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
        return ss

    # ---------------- AES encrypt/decrypt ----------------
    def encrypt(self, plaintext: bytes, aad: bytes = None):
        """
        AES-256-GCM authenticated encryption.
        """
        if self.aes_key is None:
            raise ValueError("AES key not initialized. Perform key exchange first.")

        if aad is None:
            aad = self.aad

        res = encrypt_aes_gcm(plaintext, self.aes_key, associated_data=aad)
        return res["nonce"], res["ciphertext"]

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
        """
        AES-256-GCM authenticated decryption.
        """
        if self.aes_key is None:
            raise ValueError("AES key not initialized. Perform key exchange first.")

        if aad is None:
            aad = self.aad

        return decrypt_aes_gcm(nonce, ciphertext, self.aes_key, associated_data=aad)

    # ---------------- Cleanup ----------------
    def close(self) -> None:
        try:
            if hasattr(self.kem, "free"):
                self.kem.free()
        except Exception:
            pass


# ---------------- Self-test ----------------
if __name__ == "__main__":
    print("[+] Testing CryptoManager...")

    alice = CryptoManager(role="server")
    pk = alice.generate_keys()

    bob = CryptoManager(role="client")
    ct, ss1 = bob.encapsulate(pk)

    ss2 = alice.decapsulate(ct)
    print("Shared secrets match?", ss1 == ss2)

    nonce, ct = bob.encrypt(b"Hello PQC!", aad=b"demo")
    msg = alice.decrypt(nonce, ct, aad=b"demo")
    print("Decrypted:", msg)
