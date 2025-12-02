from Backend.aes_utils import (
    derive_key_from_shared_secret,
    encrypt_aes_gcm,
    decrypt_aes_gcm
)
import os


def test_aes_gcm_encryption_decryption():
    secret = os.urandom(32)
    key = derive_key_from_shared_secret(secret)

    plaintext = b"Hello quantum world!"
    aad = b"test-header"

    encrypted = encrypt_aes_gcm(plaintext, key, aad)
    decrypted = decrypt_aes_gcm(
        encrypted["nonce"],
        encrypted["ciphertext"],
        key,
        aad
    )

    assert decrypted == plaintext
