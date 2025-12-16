"""
demo_cryptomanager.py

Standalone demo for the CryptoManager + Kyber + AES-256-GCM flow.

What it shows:
  1. Server (Alice) generates a Kyber keypair.
  2. Client (Bob) encapsulates to Alice's public key -> shared secret.
  3. Alice decapsulates -> same shared secret.
  4. Bob sends an encrypted message to Alice (client -> server direction).
  5. Alice decrypts it.
  6. Alice sends an encrypted reply to Bob (server -> client direction).
  7. We then tamper with a ciphertext to show decryption/authentication failure.
"""

from .crypto_manager import CryptoManager
from .hash_utils import fingerprint, to_hex


def print_separator(title: str) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def main() -> None:
    # 1) Create Alice (server) and Bob (client)
    print_separator("1) Create CryptoManager instances (Alice = server, Bob = client)")
    alice = CryptoManager()  # will act as server/receiver
    bob = CryptoManager()    # will act as client/sender

    # 2) Alice generates Kyber keypair
    print_separator("2) Alice generates Kyber keypair")
    alice_pk = alice.generate_keys()
    print(f"Alice's public key length: {len(alice_pk)} bytes")
    print(f"Alice's public key fingerprint: {fingerprint(alice_pk, size=8)}")

    # 3) Bob encapsulates to Alice's public key (client side)
    print_separator("3) Bob encapsulates to Alice's public key (Kyber KEM)")
    kem_ct, ss_bob = bob.encapsulate(alice_pk)
    print(f"Bob's shared secret length: {len(ss_bob)} bytes")
    print(f"KEM ciphertext length (ct): {len(kem_ct)} bytes")
    print(f"KEM ciphertext fingerprint: {fingerprint(kem_ct, size=8)}")

    # 4) Alice decapsulates (server side)
    print_separator("4) Alice decapsulates KEM ciphertext")
    ss_alice = alice.decapsulate(kem_ct)
    print(f"Alice's shared secret length: {len(ss_alice)} bytes")
    print("Shared secrets equal?", ss_bob == ss_alice)

    # At this point, BOTH alice and bob have:
    #   - key_c2s (client -> server AES-256 key)
    #   - key_s2c (server -> client AES-256 key)
    #   - aad      (SHA256(pk || ct) binding the handshake)

    # 5) Bob -> Alice: encrypted message using AES-256-GCM (client -> server)
    print_separator("5) Bob -> Alice: AES-256-GCM encrypted message")

    plaintext_bob = b"Hello, this is Bob (client -> server)!"
    print(f"Bob's plaintext: {plaintext_bob.decode()}")

    nonce1, ciphertext1 = bob.encrypt(plaintext_bob, aad=None)
    print(f"Nonce (hex):      {to_hex(nonce1)}")
    print(f"Ciphertext (hex): {to_hex(ciphertext1)[:80]}...")  # truncate for display

    # Alice decrypts
    decrypted1 = alice.decrypt(nonce1, ciphertext1, aad=None)
    print(f"Alice decrypted:  {decrypted1.decode()}")

    # 6) Alice -> Bob: encrypted message using AES-256-GCM (server -> client)
    print_separator("6) Alice -> Bob: AES-256-GCM encrypted reply")

    plaintext_alice = b"Hello Bob, this is Alice (server -> client)!"
    print(f"Alice's plaintext: {plaintext_alice.decode()}")

    nonce2, ciphertext2 = alice.encrypt(plaintext_alice, aad=None)
    print(f"Nonce (hex):      {to_hex(nonce2)}")
    print(f"Ciphertext (hex): {to_hex(ciphertext2)[:80]}...")

    # Bob decrypts
    decrypted2 = bob.decrypt(nonce2, ciphertext2, aad=None)
    print(f"Bob decrypted:    {decrypted2.decode()}")

    # 7) Tampering demo: modify ciphertext and show decryption/auth failure
    print_separator("7) Tampering demo: flip one bit in ciphertext and decrypt")

    tampered = bytearray(ciphertext1)
    tampered[0] ^= 0x01  # flip the lowest bit of the first byte
    tampered = bytes(tampered)
    print("Original ciphertext (first byte, hex):", to_hex(ciphertext1[:1]))
    print("Tampered ciphertext (first byte, hex):", to_hex(tampered[:1]))

    try:
        _ = alice.decrypt(nonce1, tampered, aad=None)
        print("Unexpected: tampered ciphertext decrypted successfully (this should NOT happen!)")
    except Exception as e:
        print("Expected failure when decrypting tampered ciphertext:")
        print(f"  {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
