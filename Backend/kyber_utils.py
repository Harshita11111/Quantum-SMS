# Backend/kyber_utils.py
"""
Kyber utilities with a safe fallback.

Behavior:
- If the `oqs` binding is importable, use it (calls into liboqs).
- Otherwise use a deterministic pure-Python mock based on AES-GCM (PyCryptodome)
  which *simulates* the same API (generate_keypair, encapsulate, decapsulate).
  The mock is NOT post-quantum secure and is only for local development/testing
  on Windows without liboqs/pyoqs.

Exported functions:
- generate_kyber_keypair(algorithm="Kyber512") -> (public_key_bytes, secret_key_bytes)
- kyber_encapsulate(public_key: bytes, algorithm="Kyber512") -> (kem_ct: bytes, shared_secret: bytes)
- kyber_decapsulate(ciphertext: bytes, secret_key: bytes, algorithm="Kyber512") -> shared_secret: bytes
"""

from typing import Tuple

# Try to use real liboqs (oqs). If unavailable, fall back to pure-Python mock.
try:
    import oqs  # type: ignore
    _HAVE_OQS = True
except Exception:
    oqs = None  # type: ignore
    _HAVE_OQS = False

# If we don't have oqs, import PyCryptodome helpers for the mock.
if not _HAVE_OQS:
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise RuntimeError(
            "No oqs and no pycryptodome available. Install pycryptodome "
            "in your venv: pip install pycryptodome"
        ) from e


# ----------------------- Real oqs-backed implementations -----------------------
if _HAVE_OQS:

    def generate_kyber_keypair(algorithm: str = "Kyber512") -> Tuple[bytes, bytes]:
        """
        Generate keypair using liboqs. Returns (public_key, secret_key).
        This handles liboqs bindings where secret key must be exported manually.
        """
        kem = oqs.KeyEncapsulation(algorithm)

        # Preferred: kem.generate_keypair() may return public key only;
        # some bindings require export of secret via export_secret_key().
        if hasattr(kem, "generate_keypair"):
            try:
                pub = kem.generate_keypair()
            except TypeError:
                # older/newer variants may return tuple
                pub = kem.generate_keypair()
            # Export secret key if binding supports it
            if hasattr(kem, "export_secret_key"):
                sk = kem.export_secret_key()
            else:
                # If no export function, try to call oqs.generate_keypair
                try:
                    pub2, sk = oqs.generate_keypair(algorithm)
                    pub = pub2
                except Exception:
                    raise RuntimeError("Cannot obtain secret key from oqs binding")
            return pub, sk

        # fallback: try oqs.generate_keypair
        try:
            pub, sk = oqs.generate_keypair(algorithm)
            return pub, sk
        except Exception as e:
            raise RuntimeError("oqs binding does not expose generate_keypair") from e


    def kyber_encapsulate(public_key: bytes, algorithm: str = "Kyber512") -> Tuple[bytes, bytes]:
        """
        Encapsulate using liboqs KeyEncapsulation. Returns (kem_ct, shared_secret).
        Tries several possible method names to be compatible across oqs versions.
        """
        kem = oqs.KeyEncapsulation(algorithm)
        methods = ["encap_secret", "encapsulate", "encap", "encapsulate_secret"]
        for name in methods:
            if hasattr(kem, name):
                fn = getattr(kem, name)
                try:
                    return fn(public_key)
                except TypeError:
                    continue
        # fallback: try top-level helper
        try:
            return kem.encapsulate(public_key)
        except Exception as e:
            raise RuntimeError("No supported encapsulation method found in oqs binding") from e


    def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, algorithm: str = "Kyber512") -> bytes:
        """
        Decapsulate using liboqs KeyEncapsulation. Some liboqs builds require importing the
        secret key into a fresh KeyEncapsulation object first.
        """
        kem = oqs.KeyEncapsulation(algorithm)
        if hasattr(kem, "import_secret_key"):
            kem.import_secret_key(secret_key)
        methods = ["decap_secret", "decapsulate", "decap", "decapsulate_secret"]
        for name in methods:
            if hasattr(kem, name):
                fn = getattr(kem, name)
                try:
                    return fn(ciphertext)
                except Exception:
                    continue
        # fallback
        try:
            return kem.decapsulate(ciphertext)
        except Exception as e:
            raise RuntimeError("No supported decapsulation method found in oqs binding") from e

# ----------------------- Pure-Python mock implementations -----------------------
else:

    def generate_kyber_keypair(algorithm: str = "Kyber512") -> Tuple[bytes, bytes]:
        """
        Create a random (public, private) pair (both 32 bytes) for dev/testing.
        """
        pk = get_random_bytes(32)
        sk = get_random_bytes(32)
        return pk, sk

    def kyber_encapsulate(public_key: bytes, algorithm: str = "Kyber512") -> Tuple[bytes, bytes]:
        """
        Mock encapsulation:
        - produce a random 32-byte shared_secret
        - encrypt it under an AES key derived from public_key (padded/truncated to 32)
        - return kem_ct = nonce || ct || tag, and shared_secret
        """
        shared_secret = get_random_bytes(32)
        aes_key = (public_key + b"\x00" * 32)[:32]
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(shared_secret)
        kem_ct = cipher.nonce + ct + tag
        return kem_ct, shared_secret

    def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, algorithm: str = "Kyber512") -> bytes:
        """
        Mock decapsulation:
        - derive AES key from secret_key and decrypt kem_ct to recover shared_secret
        """
        nonce = ciphertext[:16]
        ct = ciphertext[16:-16]
        tag = ciphertext[-16:]
        aes_key = (secret_key + b"\x00" * 32)[:32]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        shared_secret = cipher.decrypt_and_verify(ct, tag)
        return shared_secret
