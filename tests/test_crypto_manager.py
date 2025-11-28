import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend.crypto_manager import CryptoManager


def test_crypto_manager():
    alice = CryptoManager()
    bob = CryptoManager()

    pk, _ = alice.generate_keys()
    ct, ss1 = bob.encapsulate(pk)
    ss2 = alice.decapsulate(ct)

    assert ss1 == ss2, "Shared secrets mismatch"

    nonce, ciphertext = bob.encrypt(b"quantum message", aad=b"hdr")
    decrypted = alice.decrypt(nonce, ciphertext, aad=b"hdr")

    assert decrypted == b"quantum message"
