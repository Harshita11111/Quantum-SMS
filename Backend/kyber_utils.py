# Backend/kyber_utils.py
"""
Kyber utilities compatible with liboqs-python builds that DO NOT keep
secret_key internally in the KeyEncapsulation object.
That means decapsulation MUST receive the secret key.
"""

import oqs


# ========================================
#  KEY GENERATION
# ========================================
def generate_kyber_keypair(algorithm="Kyber512"):
    kem = oqs.KeyEncapsulation(algorithm)

    # Works for all liboqs versions
    if hasattr(kem, "generate_keypair"):
        public_key = kem.generate_keypair()

        # secret key must ALWAYS be exported manually
        if hasattr(kem, "export_secret_key"):
            secret_key = kem.export_secret_key()
        else:
            raise RuntimeError("This liboqs version cannot export secret key.")

        return public_key, secret_key

    raise RuntimeError("generate_keypair() not available in this liboqs build.")


# ========================================
#  ENCAPSULATION  (client-side)
# ========================================
def kyber_encapsulate(public_key: bytes, algorithm="Kyber512"):
    kem = oqs.KeyEncapsulation(algorithm)

    methods = [
        "encap_secret",
        "encap",
        "encapsulate",
        "encapsulate_secret",
    ]

    for m in methods:
        if hasattr(kem, m):
            fn = getattr(kem, m)
            try:
                ct, ss = fn(public_key)
                return ct, ss
            except TypeError:
                continue

    raise AttributeError("No supported Kyber encapsulation function found.")


# ========================================
#  DECAPSULATION  (server-side)
# ========================================
def kyber_decapsulate(ciphertext: bytes, secret_key: bytes, algorithm="Kyber512"):
    """
    Decapsulation MUST receive secret_key manually for your liboqs build.
    """

    kem = oqs.KeyEncapsulation(algorithm)

    # restore secret key into this new object
    if hasattr(kem, "import_secret_key"):
        kem.import_secret_key(secret_key)
    else:
        raise RuntimeError("This liboqs version cannot import secret key.")

    # Try various decapsulation method names
    methods = [
        "decap_secret",
        "decapsulate",
        "decap",
        "decapsulate_secret",
    ]

    for m in methods:
        if hasattr(kem, m):
            fn = getattr(kem, m)
            try:
                # your liboqs decap always needs: ss = fn(ciphertext)
                ss = fn(ciphertext)
                return ss
            except Exception:
                continue

    raise AttributeError("No supported Kyber decapsulation function in this liboqs build.")
