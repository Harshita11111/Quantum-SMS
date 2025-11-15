"""
crypto_manager.py
------------------
High-level cryptography manager for Quantum-Safe Messaging System.

This file is robust to small API differences between liboqs-python versions.
It uses the AES helpers from aes_utils.py:
  - derive_key_from_shared_secret(shared_secret, salt=None, info=None, length=32)
  - encrypt_aes_gcm(plaintext, key, associated_data=None, nonce=None) -> {'nonce','ciphertext'}
  - decrypt_aes_gcm(nonce, ciphertext, key, associated_data=None) -> plaintext
"""

from __future__ import annotations
from typing import Optional, Tuple

# oqs KeyEncapsulation (liboqs-python)
import oqs  # we import module and use KeyEncapsulation via oqs.KeyEncapsulation

# AES helpers you provided earlier
from aes_utils import encrypt_aes_gcm, decrypt_aes_gcm, derive_key_from_shared_secret


class CryptoManager:
    def __init__(self, algorithm: str = "Kyber512"):
        self.algorithm = algorithm
        # Server-side KEM object (will hold secret for decapsulation in many oqs builds)
        self.kem = oqs.KeyEncapsulation(self.algorithm)
        self.public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None

    # ---------------- Key generation (server/receiver) ----------------
    def generate_keys(self) -> bytes:
        """
        Generate a keypair and return the public key bytes.
        Many oqs.KeyEncapsulation instances expose generate_keypair() -> public_key
        """
        # prefer instance method if present
        if hasattr(self.kem, "generate_keypair"):
            pk = self.kem.generate_keypair()
        else:
            # try module-level helper if available
            gen = getattr(oqs, "generate_keypair", None)
            if gen is not None:
                pk, sk = gen(self.algorithm)
            else:
                raise RuntimeError("No generate_keypair method found in oqs binding")
            pk = pk
        self.public_key = pk
        return pk

    # ---------------- Encapsulation (client/sender) ----------------
    def encapsulate(self, receiver_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Client-side: encapsulate to receiver_public_key.
        Returns (kem_ciphertext, shared_secret).
        Uses a fresh KeyEncapsulation instance for the sender so secret isn't required to be exported.
        """
        client_kem = oqs.KeyEncapsulation(self.algorithm)

        # Try several method names commonly used by oqs bindings
        method_candidates = ("encap_secret", "encapsulate", "encap", "encapsulate_secret")
        for name in method_candidates:
            if hasattr(client_kem, name):
                method = getattr(client_kem, name)
                try:
                    # Most signatures: method(public_key) -> (ct, shared_secret)
                    ct, ss = method(receiver_public_key)
                    self.shared_secret = ss
                    # Derive AES key (32 bytes) from shared secret
                    self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                    return ct, ss
                except TypeError:
                    # try next candidate if signature mismatch
                    continue

        # Last attempt: try a plain 'encapsulate' call (let Python raise informative error if not supported)
        try:
            ct, ss = client_kem.encapsulate(receiver_public_key)
            self.shared_secret = ss
            self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
            return ct, ss
        except Exception as e:
            raise RuntimeError(f"Failed to encapsulate (no matching method found): {e}")

    # ---------------- Decapsulation (server/receiver) ----------------
    def decapsulate(self, kem_ciphertext: bytes) -> bytes:
        """
        Server-side: decapsulate ciphertext using the server's stored KEM instance.
        Returns the shared secret and sets/derives AES key.
        """
        # Try common decap method names
        decap_candidates = ("decapsulate", "decap_secret", "decap", "decapsulate_secret")
        for name in decap_candidates:
            if hasattr(self.kem, name):
                method = getattr(self.kem, name)
                try:
                    ss = method(kem_ciphertext)
                    self.shared_secret = ss
                    self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                    return ss
                except TypeError:
                    # maybe signature expects (ct, sk_bytes) — try to export secret if available
                    try:
                        if hasattr(self.kem, "export_secret_key"):
                            sk_bytes = self.kem.export_secret_key()
                            ss = method(kem_ciphertext, sk_bytes)
                            self.shared_secret = ss
                            self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                            return ss
                    except Exception:
                        pass
                    continue

        # fallback: try generic decapsulate
        if hasattr(self.kem, "decapsulate"):
            ss = self.kem.decapsulate(kem_ciphertext)
            self.shared_secret = ss
            self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
            return ss

        raise RuntimeError("No suitable decapsulation method found on oqs.KeyEncapsulation instance")

    # ---------------- AES encrypt/decrypt ----------------
    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM using derived AES key.
        Returns (nonce, ciphertext) where ciphertext includes the tag (AESGCM.encrypt format).
        """
        if not self.aes_key:
            raise ValueError("AES key not initialized. Perform key exchange first.")
        res = encrypt_aes_gcm(plaintext, self.aes_key, associated_data=aad)
        return res["nonce"], res["ciphertext"]

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt AES-GCM ciphertext (ciphertext contains tag).
        Returns plaintext bytes or raises on authentication failure.
        """
        if not self.aes_key:
            raise ValueError("AES key not initialized. Perform key exchange first.")
        return decrypt_aes_gcm(nonce, ciphertext, self.aes_key, associated_data=aad)

    # ---------------- cleanup ----------------
    def close(self) -> None:
        try:
            if hasattr(self.kem, "free"):
                self.kem.free()
        except Exception:
            pass


# ---------------- Self-test ----------------
if __name__ == "__main__":
    print("[+] Testing CryptoManager...")

    # Receiver (Alice) - generates keys (public key returned; secret kept in alice.kem)
    alice = CryptoManager()
    pk = alice.generate_keys()

    # Sender (Bob) - encapsulates to Alice's public key
    bob = CryptoManager()
    kem_ct, ss1 = bob.encapsulate(pk)

    # Alice decapsulates
    ss2 = alice.decapsulate(kem_ct)

    print("Shared secrets equal?", ss1 == ss2)

    # Bob encrypts (aes key derived inside bob during encapsulate)
    nonce, ct = bob.encrypt(b"Quantum-safe message!", aad=b"demo")

    # Alice decrypts (aes key derived inside alice during decapsulate)
    try:
        msg = alice.decrypt(nonce, ct, aad=b"demo")
        print("Decrypted message:", msg.decode())
    except Exception as e:
        print("Decryption failed:", e)
