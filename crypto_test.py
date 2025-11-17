"""
crypto_test.py

Tests for the Quantum-Safe Messaging crypto layer.

Covers:

  kyber_utils:
    - QSMSKeySchedule: schedule determinism, direction separation
    - AES-GCM helpers (encrypt_gcm / decrypt_gcm):
        AEAD round-trip, AAD mismatch failure, tag tamper failure
    - Framing helpers (send_frame / recv_frame):
        basic round-trip, MAX_FRAME size cap

  aes_utils:
    - AES-GCM helpers (encrypt_aes_gcm / decrypt_aes_gcm):
        AEAD round-trip, AAD mismatch, tag tamper failure

  crypto_manager:
    - KEM handshake using stub or oqs
    - encrypt/decrypt both directions (client -> server, server -> client)
    - tamper + AAD mismatch must fail
"""

from __future__ import annotations

import os
import socket
import struct

import pytest
from cryptography.exceptions import InvalidTag

from qsms.crypto_manager import CryptoManager
from qsms.aes_utils import (
    derive_key_from_shared_secret,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from qsms.kyber_utils import (
    QSMSKeySchedule,
    encrypt_gcm,
    decrypt_gcm,
    MAX_FRAME,
    send_frame,
    recv_frame,
    CryptoError,
    FrameTooLargeError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def tamper_one_byte(b: bytes) -> bytes:
    if not b:
        return b
    ba = bytearray(b)
    ba[-1] ^= 0x01
    return bytes(ba)


def make_socketpair():
    """Cross-platform socketpair helper (works on Windows & POSIX)."""
    if hasattr(socket, "socketpair"):
        try:
            return socket.socketpair()
        except OSError:
            pass  # fall back below

    # Fallback: create a loopback TCP connection
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(listener.getsockname())
    server, _ = listener.accept()
    listener.close()
    return client, server


# ---------------------------------------------------------------------------
# QSMSKeySchedule tests (kyber_utils)
# ---------------------------------------------------------------------------

def test_schedule_determinism_and_shape():
    """derive() with identical inputs must yield identical keys/AAD/salt."""
    pk = random_bytes(32)
    ct = random_bytes(32)
    ss = random_bytes(32)

    s1 = QSMSKeySchedule.derive(pk, ct, ss)
    s2 = QSMSKeySchedule.derive(pk, ct, ss)

    assert s1.key_c2s == s2.key_c2s
    assert s1.key_s2c == s2.key_s2c
    assert s1.aad == s2.aad
    assert s1.salt == s2.salt

    # basic length checks
    assert len(s1.key_c2s) == 32
    assert len(s1.key_s2c) == 32
    assert len(s1.aad) == 32
    assert len(s1.salt) == 32

    # AAD is defined as salt
    assert s1.aad == s1.salt


def test_schedule_direction_separation():
    """Server->client and client->server keys must differ."""
    pk = random_bytes(32)
    ct = random_bytes(32)
    ss = random_bytes(32)

    sched = QSMSKeySchedule.derive(pk, ct, ss)
    assert sched.key_c2s != sched.key_s2c


# ---------------------------------------------------------------------------
# AES-GCM via kyber_utils (encrypt_gcm / decrypt_gcm)
# ---------------------------------------------------------------------------

def test_encrypt_gcm_round_trip():
    key = random_bytes(32)
    aad = b"test-kyber-utils-aad"
    pt = b"The quick brown fox jumps over the lazy dog"

    blob = encrypt_gcm(key, aad, pt)
    assert len(blob) >= 12 + 16  # nonce + tag at minimum

    recovered = decrypt_gcm(key, aad, blob)
    assert recovered == pt


def test_encrypt_gcm_aad_mismatch_fails():
    key = random_bytes(32)
    aad_good = b"correct-aad"
    aad_bad = b"wrong-aad"
    pt = b"secret message"

    blob = encrypt_gcm(key, aad_good, pt)

    with pytest.raises(CryptoError):
        decrypt_gcm(key, aad_bad, blob)


def test_encrypt_gcm_tamper_fails():
    key = random_bytes(32)
    aad = b"aad"
    pt = b"another secret"

    blob = encrypt_gcm(key, aad, pt)
    tampered = tamper_one_byte(blob)

    with pytest.raises(CryptoError):
        decrypt_gcm(key, aad, tampered)


# ---------------------------------------------------------------------------
# Framing tests (send_frame / recv_frame)
# ---------------------------------------------------------------------------

def test_framing_round_trip():
    c1, c2 = make_socketpair()
    try:
        payload = b"hello framed world"
        send_frame(c1, payload)
        received = recv_frame(c2)
        assert received == payload
    finally:
        c1.close()
        c2.close()


def test_send_frame_size_cap():
    """Sending a frame larger than MAX_FRAME must raise FrameTooLargeError."""
    c1, c2 = make_socketpair()
    try:
        big_payload = b"\x00" * (MAX_FRAME + 1)
        with pytest.raises(FrameTooLargeError):
            send_frame(c1, big_payload)
    finally:
        c1.close()
        c2.close()


def test_recv_frame_size_cap():
    """Receiving a header announcing > MAX_FRAME must raise FrameTooLargeError."""
    c1, c2 = make_socketpair()
    try:
        # Manually send header with length = MAX_FRAME + 1
        header = struct.pack("!I", MAX_FRAME + 1)
        c1.sendall(header)
        with pytest.raises(FrameTooLargeError):
            recv_frame(c2)
    finally:
        c1.close()
        c2.close()


# ---------------------------------------------------------------------------
# AES-GCM via aes_utils (encrypt_aes_gcm / decrypt_aes_gcm)
# ---------------------------------------------------------------------------

def test_aes_utils_aead_round_trip():
    shared_secret = random_bytes(32)
    key = derive_key_from_shared_secret(shared_secret, info=b"test-aes-utils")
    aad = b"test-aad"
    pt = b"Hello from aes_utils"

    enc = encrypt_aes_gcm(pt, key, associated_data=aad)
    nonce, ct = enc["nonce"], enc["ciphertext"]

    recovered = decrypt_aes_gcm(nonce, ct, key, associated_data=aad)
    assert recovered == pt


def test_aes_utils_aad_mismatch_fails():
    shared_secret = random_bytes(32)
    key = derive_key_from_shared_secret(shared_secret, info=b"aes-utils-aad")
    aad_good = b"correct"
    aad_bad = b"wrong"
    pt = b"secret under aes_utils"

    enc = encrypt_aes_gcm(pt, key, associated_data=aad_good)
    nonce, ct = enc["nonce"], enc["ciphertext"]

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(nonce, ct, key, associated_data=aad_bad)


def test_aes_utils_tag_tamper_fails():
    shared_secret = random_bytes(32)
    key = derive_key_from_shared_secret(shared_secret, info=b"aes-utils-tamper")
    aad = b"aad"
    pt = b"another aes_utils secret"

    enc = encrypt_aes_gcm(pt, key, associated_data=aad)
    nonce, ct = enc["nonce"], enc["ciphertext"]
    tampered_ct = tamper_one_byte(ct)

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(nonce, tampered_ct, key, associated_data=aad)


# ---------------------------------------------------------------------------
# CryptoManager integration tests
# ---------------------------------------------------------------------------

def _handshake_pair():
    """Helper: perform a full client/server KEM handshake."""
    # Server (Alice)
    alice = CryptoManager()
    server_pk = alice.generate_keys()

    # Client (Bob)
    bob = CryptoManager()
    kem_ct, ss_client = bob.encapsulate(server_pk)

    # Server decapsulates
    ss_server = alice.decapsulate(kem_ct)

    return alice, bob, ss_client, ss_server


def test_crypto_manager_handshake_and_keys():
    alice, bob, ss_client, ss_server = _handshake_pair()

    # Shared secret must match
    assert ss_client == ss_server
    assert alice.shared_secret == bob.shared_secret == ss_client

    # Roles
    assert alice.role == "server"
    assert bob.role == "client"

    # Directional keys and AAD must match cross-side
    assert alice.key_c2s == bob.key_c2s
    assert alice.key_s2c == bob.key_s2c
    assert alice.aad == bob.aad

    # Keys must not be None and must be 32 bytes (AES-256)
    for key in (alice.key_c2s, alice.key_s2c, bob.key_c2s, bob.key_s2c):
        assert isinstance(key, bytes)
        assert len(key) == 32


def test_crypto_manager_encrypt_decrypt_both_directions():
    alice, bob, _, _ = _handshake_pair()

    # Client -> Server
    msg_c2s = b"Hello from client!"
    n1, c1 = bob.encrypt(msg_c2s)  # uses bob.aad by default
    got_c2s = alice.decrypt(n1, c1)
    assert got_c2s == msg_c2s

    # Server -> Client
    msg_s2c = b"Hello from server!"
    n2, c2 = alice.encrypt(msg_s2c)
    got_s2c = bob.decrypt(n2, c2)
    assert got_s2c == msg_s2c


def test_crypto_manager_tamper_and_aad_mismatch_failures():
    alice, bob, _, _ = _handshake_pair()

    pt = b"integrity-protected payload"
    nonce, ct = bob.encrypt(pt)

    # 1) Tamper ciphertext
    tampered_ct = tamper_one_byte(ct)
    with pytest.raises(InvalidTag):
        alice.decrypt(nonce, tampered_ct)

    # 2) Explicit AAD mismatch
    wrong_aad = b"definitely-wrong-aad"
    with pytest.raises(InvalidTag):
        alice.decrypt(nonce, ct, aad=wrong_aad)
