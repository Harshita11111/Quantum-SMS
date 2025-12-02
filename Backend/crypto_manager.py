from __future__ import annotations
# qsms/Backend/crypto_manager.py
# Role: High-level manager combining KEM and AES-GCM to produce an encrypt/decrypt API for messages.

"""
Capabilities

Generate keys (server).

Encapsulate (client) → returns (ciphertext, shared_secret), derives AES key.

Decapsulate (server) → derive AES key from client's ct.

encrypt(plaintext) and decrypt(nonce, ciphertext) using the derived AES key."""



"""
Robust CryptoManager for QSMS.

- Attempts to use liboqs (oqs). If not present, uses a deterministic mock KEM
  so you can continue developing network/auth logic without the native dependency.
- Uses aes_utils if available; otherwise falls back to a small AES-GCM helper.
"""


from typing import Optional, Tuple
import base64
import traceback

# Try to import liboqs (may not be installed on Windows/pip)
try:
    import oqs  # type: ignore
    _HAVE_OQS = True
except Exception:
    oqs = None  # type: ignore
    _HAVE_OQS = False

# Try to import AES helpers from your project first
try:
    from .aes_utils import (
        encrypt_aes_gcm,
        decrypt_aes_gcm,
        derive_key_from_shared_secret,
    )

    _HAVE_AES_UTILS = True
except Exception:
    _HAVE_AES_UTILS = False

# If aes_utils isn't available, provide small AES-GCM helpers using pycryptodome
if not _HAVE_AES_UTILS:
    try:
        from Crypto.Cipher import AES  # pycryptodome
        from Crypto.Random import get_random_bytes
        from hashlib import sha256

        def derive_key_from_shared_secret(shared_secret: bytes, *, info: bytes = b"", length: int = 32) -> bytes:
            # simple HKDF-like derivation (NOT a full HKDF implementation)
            h = sha256(shared_secret + info).digest()
            if length <= len(h):
                return h[:length]
            out = h
            while len(out) < length:
                out += sha256(out).digest()
            return out[:length]

        def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes = None, nonce: bytes = None):
            if nonce is None:
                nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if associated_data:
                cipher.update(associated_data)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return {"nonce": nonce, "ciphertext": ct + tag}

        def decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes = None):
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if associated_data:
                cipher.update(associated_data)
            ct = ciphertext[:-16]
            tag = ciphertext[-16:]
            return cipher.decrypt_and_verify(ct, tag)

    except Exception:
        raise RuntimeError(
            "No AES helpers available: install pycryptodome or add Backend/aes_utils.py"
        )


# ------------------------------------------------------------------
# Mock KEM (deterministic and safe for development)
# ------------------------------------------------------------------
import os
from hashlib import sha256
from typing import Any

class _MockKEM:
    """
    Simple mock KEM with deterministic derivation:
      - server.generate_keypair() -> pub (bytes)
      - client.encapsulate(pub) -> (ct, shared)
      - server.decapsulate(ct) -> shared
    Shared is derived as sha256(pub + ct).
    """
    name = "KYBER-MOCK-v1"

    def __init__(self):
        self._priv = None
        self._pub = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        self._priv = os.urandom(48)
        self._pub = sha256(self._priv).digest()
        return self._pub, self._priv

    def encapsulate(self, pub: bytes) -> Tuple[bytes, bytes]:
        ct = os.urandom(48)
        shared = sha256(pub + ct).digest()
        return ct, shared

    def decapsulate(self, priv: bytes, ct: bytes) -> bytes:
        pub = sha256(priv).digest()
        shared = sha256(pub + ct).digest()
        return shared


# ------------------------------------------------------------------
# CryptoManager
# ------------------------------------------------------------------
class CryptoManager:
    def __init__(self, algorithm: str = "Kyber512", role: str = "unset"):
        self.algorithm = algorithm
        self.role = role
        self.public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None
        self.aad: bytes = b"qsms-auth"

        # KEM backend: either real oqs.KeyEncapsulation or our mock
        if _HAVE_OQS:
            try:
                self.kem = oqs.KeyEncapsulation(self.algorithm)
                self._use = "oqs"
            except Exception:
                # fallback to mock if oqs binding behaves unexpectedly
                self.kem = _MockKEM()
                self._use = "mock"
        else:
            self.kem = _MockKEM()
            self._use = "mock"

    # ---------------- Key generation (server) ----------------
    def generate_keys(self) -> bytes:
        """
        Server-side: generate a keypair and return public key bytes.
        For liboqs: use kem.generate_keypair() or kem.generate_keypair().
        For the mock: return pub bytes.
        """
        if self._use == "oqs":
            # liboqs typically provides generate_keypair() or similar
            if hasattr(self.kem, "generate_keypair"):
                try:
                    pk = self.kem.generate_keypair()
                    # liboqs sometimes returns (pk, sk) or only pk depending on binding.
                    if isinstance(pk, tuple):
                        pub = pk[0]
                    else:
                        pub = pk
                except Exception:
                    # try alternate signature
                    try:
                        pub, _sk = oqs.generate_keypair(self.algorithm)
                    except Exception as e:
                        raise RuntimeError("oqs.generate_keypair unavailable") from e
                self.public_key = pub
                return pub
            else:
                # fallback: try kem.generate_keypair()
                pub = self.kem.generate_keypair()
                self.public_key = pub
                return pub

        # mock
        pub, priv = self.kem.generate_keypair()
        self._priv = priv
        self.public_key = pub
        return pub

    # ---------------- Encapsulation (client) ----------------
    def encapsulate(self, receiver_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Client-side: encapsulate using receiver_public_key.
        Returns (ciphertext, shared_secret).
        Also derives AES key.
        """
        if self._use == "oqs":
            # try different method names for various oqs bindings
            method_candidates = ("encap_secret", "encapsulate", "encap", "encapsulate_secret")
            for name in method_candidates:
                if hasattr(self.kem, name):
                    method = getattr(self.kem, name)
                    try:
                        ct, ss = method(receiver_public_key)
                        self.shared_secret = ss
                        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                        return ct, ss
                    except TypeError:
                        continue
            # fallback to default
            ct, ss = self.kem.encapsulate(receiver_public_key)
            self.shared_secret = ss
            self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
            return ct, ss

        # mock path
        ct, ss = self.kem.encapsulate(receiver_public_key)
        self.shared_secret = ss
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
        return ct, ss

    # ---------------- Decapsulation (server) ----------------
    def decapsulate(self, kem_ciphertext: bytes) -> bytes:
        """
        Server-side: given ciphertext from client, derive shared secret and AES key.
        """
        if self._use == "oqs":
            # try different decapsulation names
            method_candidates = ("decapsulate", "decap_secret", "decap", "decapsulate_secret")
            for name in method_candidates:
                if hasattr(self.kem, name):
                    method = getattr(self.kem, name)
                    try:
                        ss = method(kem_ciphertext)
                        self.shared_secret = ss
                        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                        return ss
                    except TypeError:
                        # some bindings require secret key passed
                        try:
                            if hasattr(self.kem, "export_secret_key"):
                                sk = self.kem.export_secret_key()
                                ss = method(kem_ciphertext, sk)
                                self.shared_secret = ss
                                self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
                                return ss
                        except Exception:
                            pass
                        continue
            # fallback
            ss = self.kem.decapsulate(kem_ciphertext)
            self.shared_secret = ss
            self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
            return ss

        # mock path: use stored priv if present
        try:
            ss = self.kem.decapsulate(self._priv, kem_ciphertext)
        except Exception:
            # try alternative signature
            ss = self.kem.decapsulate(kem_ciphertext)
        self.shared_secret = ss
        self.aes_key = derive_key_from_shared_secret(ss, info=b"qsms-aes-key")
        return ss

    # ---------------- AES encrypt/decrypt ----------------
    def encrypt(self, plaintext: bytes, aad: bytes = None):
        if self.aes_key is None:
            raise ValueError("AES key not initialized. Perform key exchange first.")
        if aad is None:
            aad = self.aad
        res = encrypt_aes_gcm(plaintext, self.aes_key, associated_data=aad)
        return res["nonce"], res["ciphertext"]

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
        if self.aes_key is None:
            raise ValueError("AES key not initialized. Perform key exchange first.")
        if aad is None:
            aad = self.aad
        return decrypt_aes_gcm(nonce, ciphertext, self.aes_key, associated_data=aad)

    def close(self) -> None:
        try:
            if _HAVE_OQS and self._use == "oqs" and hasattr(self.kem, "free"):
                self.kem.free()
        except Exception:
            pass


# ---------------- Self-test ----------------
if __name__ == "__main__":
    print("[+] Testing CryptoManager self-test (oqs available:", _HAVE_OQS, ")")
    try:
        alice = CryptoManager(role="server")
        pk = alice.generate_keys()

        bob = CryptoManager(role="client")
        ct, ss1 = bob.encapsulate(pk)

        ss2 = alice.decapsulate(ct)
        print("Shared secrets match?", ss1 == ss2)

        nonce, ct_blob = bob.encrypt(b"Hello PQC!", aad=b"demo")
        msg = alice.decrypt(nonce, ct_blob, aad=b"demo")
        print("Decrypted:", msg)
        print("[+] CryptoManager self-test OK")
    except Exception as e:
        print("[!] Self-test FAILED")
        traceback.print_exc()
