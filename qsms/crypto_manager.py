"""
crypto_manager.py
------------------
High-level cryptography manager for Quantum-Safe Messaging System.

Now integrates the key-exchange binding from kyber_utils:
  - After encapsulation/decapsulation we derive a directional key schedule via
      QSMSKeySchedule.derive(server_public_key, kem_ciphertext, shared_secret)
    which yields:
      * key_c2s (client -> server)   AES-256 key
      * key_s2c (server -> client)   AES-256 key
      * aad  = SHA256(pk || ct)      AAD to bind app data to the handshake

This file remains robust to small API differences between liboqs-python versions.
It uses AES helpers from aes_utils:
  - derive_key_from_shared_secret(shared_secret, salt=None, info=None, length=32)
  - encrypt_aes_gcm(plaintext, key, associated_data=None, nonce=None) -> {'nonce','ciphertext'}
  - decrypt_aes_gcm(nonce, ciphertext, key, associated_data=None) -> plaintext
"""

from __future__ import annotations
from typing import Optional, Tuple

import os
import hashlib
import warnings

# Try to import oqs. If present, we'll probe for KeyEncapsulation.
try:
    import oqs  # type: ignore
    _HAS_OQS = True
    _OQS_HAS_KEYENCAP = hasattr(oqs, "KeyEncapsulation")
except Exception:
    oqs = None  # type: ignore
    _HAS_OQS = False
    _OQS_HAS_KEYENCAP = False

# Local package imports (package-relative). If your files are flat, drop the leading dot.
from .aes_utils import encrypt_aes_gcm, decrypt_aes_gcm, derive_key_from_shared_secret
from .kyber_utils import QSMSKeySchedule


# --- Simple KEM stub for local integration testing ONLY ---
# Behavior:
#  - generate_keypair() -> returns public_key (random 32 bytes)
#  - encapsulate(receiver_public_key) -> (ct, shared_secret)
#  - decapsulate(ct) -> shared_secret computed from server's stored public key
#
# This ensures encapsulate/decapsulate compute the same shared_secret when
# receiver_public_key matches the server instance's public_key.
class _StubKEM:
    def __init__(self, algorithm: str = "STUB-KEM"):
        self.algorithm = algorithm
        self._public_key: Optional[bytes] = None

    def generate_keypair(self) -> bytes:
        pk = os.urandom(32)
        self._public_key = pk
        return pk

    # client-side encapsulation
    def encapsulate(self, receiver_public_key: bytes) -> Tuple[bytes, bytes]:
        if not isinstance(receiver_public_key, (bytes, bytearray)):
            raise TypeError("receiver_public_key must be bytes")
        nonce = os.urandom(32)
        ss = hashlib.sha256(receiver_public_key + nonce).digest()
        return nonce, ss

    # server-side decapsulation
    def decapsulate(self, ct: bytes) -> bytes:
        if self._public_key is None:
            raise RuntimeError("server keypair not generated")
        ss = hashlib.sha256(self._public_key + ct).digest()
        return ss

    # compatibility helpers used in some bindings
    def export_secret_key(self) -> bytes:
        return bytes(self._public_key or b"")


def _create_kem_instance(algorithm: str = "Kyber512"):
    """
    Return an object exposing generate_keypair(), encapsulate(pubkey) and decapsulate(ct).
    Prefer real oqs.KeyEncapsulation if available; otherwise return stub.
    """
    if _HAS_OQS and _OQS_HAS_KEYENCAP:
        try:
            return oqs.KeyEncapsulation(algorithm)  # type: ignore
        except Exception:
            warnings.warn("oqs.KeyEncapsulation exists but failed to instantiate — using test stub instead")
            return _StubKEM(algorithm)
    else:
        if _HAS_OQS and not _OQS_HAS_KEYENCAP:
            warnings.warn("oqs module installed but missing KeyEncapsulation; using test KEM stub for integration tests.")
        else:
            warnings.warn("No oqs module found; using test KEM stub for integration tests.")
        return _StubKEM(algorithm)


class CryptoManager:
    """
    High-level façade around the KEM+AES flow.

    After a successful handshake:
      - self.role in {"client","server"}
      - self.key_c2s (AES-256): key to decrypt messages coming client->server
      - self.key_s2c (AES-256): key to decrypt messages coming server->client
      - self.aad: AAD to use for AES-GCM (SHA256(pk||ct))

    For convenience, encrypt()/decrypt() choose the appropriate key automatically
    given the current role:
      - role == "client": encrypt() uses key_c2s, decrypt() uses key_s2c
      - role == "server": encrypt() uses key_s2c, decrypt() uses key_c2s
    """

    def __init__(self, algorithm: str = "Kyber512"):
        self.algorithm = algorithm
        # Server-side KEM object (either real oqs.KeyEncapsulation or test stub)
        self.kem = _create_kem_instance(self.algorithm)

        # KEM artifacts
        self.public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None

        # Directional AES keys and AAD (set after handshake)
        self.key_c2s: Optional[bytes] = None
        self.key_s2c: Optional[bytes] = None
        self.aad: Optional[bytes] = None

        # Back-compat single AES key (set in earlier versions)
        self.aes_key: Optional[bytes] = None

        # role: "client" after encapsulate(), "server" after decapsulate()
        self.role: Optional[str] = None

    # ---------------- Key generation (server/receiver) ----------------
    def generate_keys(self) -> bytes:
        """
        Generate a keypair and return the public key bytes.
        Many oqs.KeyEncapsulation instances expose generate_keypair() -> public_key
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

    # ---------------- Encapsulation (client/sender) ----------------
    def encapsulate(self, receiver_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Client-side: encapsulate to receiver_public_key.
        Returns (kem_ciphertext, shared_secret).
        Also derives directional AES keys and AAD bound to the transcript.
        """
        client_kem = _create_kem_instance(self.algorithm)

        # Try several method names commonly used by oqs bindings
        method_candidates = ("encap_secret", "encapsulate", "encap", "encapsulate_secret")
        for name in method_candidates:
            if hasattr(client_kem, name):
                method = getattr(client_kem, name)
                try:
                    ct, ss = method(receiver_public_key)
                    self._post_handshake_as_client(receiver_public_key, ct, ss)
                    return ct, ss
                except TypeError:
                    continue

        # Last attempt: vanilla encapsulate
        ct, ss = client_kem.encapsulate(receiver_public_key)
        self._post_handshake_as_client(receiver_public_key, ct, ss)
        return ct, ss

    # ---------------- Decapsulation (server/receiver) ----------------
    def decapsulate(self, kem_ciphertext: bytes) -> bytes:
        """
        Server-side: decapsulate ciphertext using the server's stored KEM instance.
        Returns the shared secret and derives directional AES keys + AAD.
        """
        decap_candidates = ("decapsulate", "decap_secret", "decap", "decapsulate_secret")
        for name in decap_candidates:
            if hasattr(self.kem, name):
                method = getattr(self.kem, name)
                try:
                    ss = method(kem_ciphertext)
                    self._post_handshake_as_server(kem_ciphertext, ss)
                    return ss
                except TypeError:
                    try:
                        if hasattr(self.kem, "export_secret_key"):
                            sk_bytes = self.kem.export_secret_key()
                            ss = method(kem_ciphertext, sk_bytes)
                            self._post_handshake_as_server(kem_ciphertext, ss)
                            return ss
                    except Exception:
                        pass
                    continue

        if hasattr(self.kem, "decapsulate"):
            ss = self.kem.decapsulate(kem_ciphertext)
            self._post_handshake_as_server(kem_ciphertext, ss)
            return ss

        raise RuntimeError("No suitable decapsulation method found on oqs.KeyEncapsulation instance")

    # ---------------- AES encrypt/decrypt (direction-aware) ----------------
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM using the OUTGOING directional key for this role.
          - client role uses key_c2s
          - server role uses key_s2c

        Returns (nonce, ciphertext) where ciphertext includes the tag.
        """
        key = self._key_outgoing()
        aad_bytes = aad if aad is not None else self._aad_required()
        res = encrypt_aes_gcm(plaintext, key, associated_data=aad_bytes)
        return res["nonce"], res["ciphertext"]

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt AES-GCM ciphertext using the INCOMING directional key for this role.
          - client role uses key_s2c
          - server role uses key_c2s
        """
        key = self._key_incoming()
        aad_bytes = aad if aad is not None else self._aad_required()
        return decrypt_aes_gcm(nonce, ciphertext, key, associated_data=aad_bytes)

    # ---------------- Internals ----------------
    def _post_handshake_as_client(self, server_pk: bytes, ct: bytes, ss: bytes) -> None:
        """Store keys and AAD after client-side encapsulation."""
        self.role = "client"
        self.public_key = self.public_key or None  # client's own pk not used here
        self.shared_secret = ss
        # Back-compat single key (not used by new flows, but kept)
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")

        sched = QSMSKeySchedule.derive(server_pk, ct, ss)
        self.key_c2s = sched.key_c2s
        self.key_s2c = sched.key_s2c
        self.aad = sched.aad

    def _post_handshake_as_server(self, ct: bytes, ss: bytes) -> None:
        """Store keys and AAD after server-side decapsulation."""
        if not self.public_key:
            raise ValueError("Server public_key not set; call generate_keys() first")
        self.role = "server"
        self.shared_secret = ss
        # Back-compat single key
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")

        sched = QSMSKeySchedule.derive(self.public_key, ct, ss)
        self.key_c2s = sched.key_c2s
        self.key_s2c = sched.key_s2c
        self.aad = sched.aad

    def _key_outgoing(self) -> bytes:
        """Key to use when this side ENCRYPTS a message."""
        if self.role == "client" and self.key_c2s:
            return self.key_c2s
        if self.role == "server" and self.key_s2c:
            return self.key_s2c
        # fallback for legacy behavior
        if self.aes_key:
            return self.aes_key
        raise ValueError("No encryption key available (perform key exchange first).")

    def _key_incoming(self) -> bytes:
        """Key to use when this side DECRYPTS a message."""
        if self.role == "client" and self.key_s2c:
            return self.key_s2c
        if self.role == "server" and self.key_c2s:
            return self.key_c2s
        # fallback for legacy behavior
        if self.aes_key:
            return self.aes_key
        raise ValueError("No decryption key available (perform key exchange first).")

    def _aad_required(self) -> bytes:
        if self.aad is None:
            raise ValueError("AAD not set — perform key exchange first.")
        return self.aad

    # ---------------- cleanup ----------------
    def close(self) -> None:
        try:
            if hasattr(self.kem, "free"):
                self.kem.free()
        except Exception:
            pass


# ---------------- Self-test ----------------
if __name__ == "__main__":
    print("[+] Testing CryptoManager (directional keys)...")

    # Receiver (Alice / server)
    alice = CryptoManager()
    pk = alice.generate_keys()

    # Sender (Bob / client)
    bob = CryptoManager()
    kem_ct, ss1 = bob.encapsulate(pk)

    # Alice decapsulates
    ss2 = alice.decapsulate(kem_ct)
    print("Shared secrets equal?", ss1 == ss2)

    # Bob -> Alice (client -> server) : bob encrypts with key_c2s, alice decrypts with key_c2s
    n1, c1 = bob.encrypt(b"Hello from client!", aad=None)   # uses bob.aad by default
    m1 = alice.decrypt(n1, c1, aad=None)
    print("Alice got:", m1.decode())

    # Alice -> Bob (server -> client)
    n2, c2 = alice.encrypt(b"Hello from server!", aad=None)
    m2 = bob.decrypt(n2, c2, aad=None)
    print("Bob got:", m2.decode())
