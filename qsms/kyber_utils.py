
"""
kyber_utils.py — Utilities for Quantum Secure Message System (QSMS)

This module contains transport framing helpers, HKDF-SHA256 key derivation,
and AES-GCM helpers for a Kyber768-based secure channel.

Design choices:
- Frame transport: 4-byte big-endian length prefix (cap to avoid OOM/DoS)
- Key schedule: HKDF-SHA256 with salt = SHA256(pk || ct)
- Directional keys: key_s2c (server->client), key_c2s (client->server)
- AEAD AAD: SHA256(pk || ct) binds app data to the handshake transcript
- Nonces: 12 random bytes per message; per-direction key separation prevents
  cross-direction nonce reuse collisions.

Dependencies:
    pip install pycryptodome
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


# ========= Constants =========

#: Human-readable protocol label used as HKDF "info"
PROTOCOL_INFO: bytes = b"qsms-v1"

#: Maximum allowed frame payload size (in bytes)
MAX_FRAME: int = 16 * 1024 * 1024  # 16 MiB — tune as needed

#: AES-GCM nonce size (bytes)
GCM_NONCE_BYTES: int = 12

#: AES-GCM authentication tag size (bytes)
GCM_TAG_BYTES: int = 16


# ========= Exceptions =========

class KyberUtilsError(Exception):
    """Base exception for QSMS utility errors."""


class FrameTooLargeError(KyberUtilsError):
    """Raised when a received or to-be-sent frame exceeds MAX_FRAME."""


class FrameIOError(KyberUtilsError):
    """Raised on framing I/O errors (connection closed, partial reads, etc.)."""


class CryptoError(KyberUtilsError):
    """Raised on cryptographic misuse or verification failures."""


# ========= Framing helpers =========

def send_frame(conn: socket.socket, payload: bytes) -> None:
    """
    Send a single length-prefixed frame over a stream socket.

    Frame format: 4-byte big-endian length || payload
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    length = len(payload)
    if length > MAX_FRAME:
        raise FrameTooLargeError(f"payload too large ({length} > {MAX_FRAME})")
    header = struct.pack("!I", length)
    conn.sendall(header + payload)


def recv_frame(conn: socket.socket) -> bytes:
    """
    Receive a single length-prefixed frame from a stream socket.

    Returns:
        The payload bytes.
    Raises:
        FrameIOError: on premature connection close.
        FrameTooLargeError: if the announced size exceeds MAX_FRAME.
    """
    hdr = b""
    while len(hdr) < 4:
        chunk = conn.recv(4 - len(hdr))
        if not chunk:
            raise FrameIOError("connection closed while reading frame header")
        hdr += chunk

    (length,) = struct.unpack("!I", hdr)
    if length > MAX_FRAME:
        raise FrameTooLargeError(f"frame too large ({length} > {MAX_FRAME})")

    buf = bytearray(length)
    view = memoryview(buf)
    nread = 0
    while nread < length:
        m = conn.recv_into(view[nread:])
        if not m:
            raise FrameIOError("connection closed while reading frame payload")
        nread += m
    return bytes(buf)


# ========= HKDF and key schedule =========

def hkdf_expand_256(master: bytes, *, salt: bytes, info: bytes) -> bytes:
    """
    HKDF-SHA256 expand to a 256-bit key.

    Args:
        master: Input keying material (IKM), e.g., Kyber shared secret.
        salt: HKDF salt (should be public, per-session).
        info: Context string to separate keys/usages.

    Returns:
        32-byte key.
    """
    if not (isinstance(master, (bytes, bytearray)) and
            isinstance(salt, (bytes, bytearray)) and
            isinstance(info, (bytes, bytearray))):
        raise TypeError("master, salt, and info must be bytes-like")
    return HKDF(master=master, key_len=32, salt=salt, hashmod=SHA256, context=info)


@dataclass(frozen=True)
class KeySchedule:
    """
    Directional keys and AAD for an authenticated, bound secure channel.

    key_s2c: key for messages sent from server to client
    key_c2s: key for messages sent from client to server
    aad: associated data to supply to AES-GCM (binds to handshake)
    salt: HKDF salt used to derive the keys (for debugging/telemetry)
    """
    key_s2c: bytes
    key_c2s: bytes
    aad: bytes
    salt: bytes


class QSMSKeySchedule:
    """
    Derive a directional key schedule from a Kyber handshake.

    Inputs:
        public_key: server's Kyber public key (bytes)
        ct: Kyber ciphertext produced by the client (bytes)
        shared_secret: Kyber shared secret (bytes)

    Derivation:
        salt  = SHA256(public_key || ct)
        aad   = salt
        key_s2c = HKDF(shared_secret, salt, info="qsms-v1|s2c")
        key_c2s = HKDF(shared_secret, salt, info="qsms-v1|c2s")
    """

    @staticmethod
    def derive(public_key: bytes, ct: bytes, shared_secret: bytes,
               *, info_base: bytes = PROTOCOL_INFO) -> KeySchedule:
        if not all(isinstance(x, (bytes, bytearray)) for x in (public_key, ct, shared_secret)):
            raise TypeError("public_key, ct, and shared_secret must be bytes-like")

        # Bind everything to the handshake transcript
        salt = SHA256.new(public_key + ct).digest()
        aad = salt  # Using the salt as AAD is compact and avoids recompute

        key_s2c = hkdf_expand_256(shared_secret, salt=salt, info=info_base + b"|s2c")
        key_c2s = hkdf_expand_256(shared_secret, salt=salt, info=info_base + b"|c2s")

        return KeySchedule(key_s2c=key_s2c, key_c2s=key_c2s, aad=aad, salt=salt)


# ========= AES-GCM helpers =========

def encrypt_gcm(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with AES-GCM and return (nonce || ciphertext || tag).

    Args:
        key: 32-byte AES key.
        aad: associated data (must be identical on decrypt).
        plaintext: bytes to encrypt.

    Returns:
        Concatenated blob: nonce(12) || ciphertext || tag(16)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    if not (isinstance(key, (bytes, bytearray)) and len(key) == 32):
        raise CryptoError("AES-GCM requires a 32-byte key")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes-like")

    nonce = os.urandom(GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def decrypt_gcm(key: bytes, aad: bytes, blob: bytes) -> bytes:
    """
    Decrypt a blob produced by encrypt_gcm.

    Args:
        key: 32-byte AES key.
        aad: associated data (must match encryption).
        blob: nonce(12) || ciphertext || tag(16)

    Returns:
        The decrypted plaintext bytes.

    Raises:
        CryptoError: on malformed input or authentication failure.
    """
    if not (isinstance(key, (bytes, bytearray)) and len(key) == 32):
        raise CryptoError("AES-GCM requires a 32-byte key")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes-like")
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes-like")

    if len(blob) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise CryptoError("ciphertext too short")

    nonce = blob[:GCM_NONCE_BYTES]
    tag = blob[-GCM_TAG_BYTES:]
    ciphertext = blob[GCM_NONCE_BYTES:-GCM_TAG_BYTES]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        # PyCryptodome raises ValueError on tag mismatch
        raise CryptoError("authentication failed") from e


# ========= Small utilities =========

def safe_utf8_decode(data: bytes) -> str:
    """
    Decode as UTF-8, replacing invalid sequences (never raises).
    Useful for logging/demo messages from untrusted peers.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return bytes(data).decode("utf-8", errors="replace")


# ========= Public API =========

__all__ = [
    "PROTOCOL_INFO",
    "MAX_FRAME",
    "GCM_NONCE_BYTES",
    "GCM_TAG_BYTES",
    "KyberUtilsError",
    "FrameTooLargeError",
    "FrameIOError",
    "CryptoError",
    "send_frame",
    "recv_frame",
    "hkdf_expand_256",
    "KeySchedule",
    "QSMSKeySchedule",
    "encrypt_gcm",
    "decrypt_gcm",
    "safe_utf8_decode",
]