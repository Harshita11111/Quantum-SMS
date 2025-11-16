"""
hash_utils.py — hashing helpers for QSMS

Purpose:
    Lightweight, dependency-free hashing utilities used across the project
    for fingerprints, integrity checks, and safe equality comparisons.

Features:
    - SHA3-256 / SHA3-512 / SHA-512 hashing for bytes and str
    - Stable, short key fingerprints (hex)
    - Constant-time equality comparison (to avoid timing leaks)
    - Hex/Base64 convenience helpers (opt-in)
    - Strict input validation

Security Notes:
    - Use UTF-8 when hashing strings (explicit)
    - Do NOT implement custom MAC here; use HMAC/AEAD in higher layers
    - Avoid logging raw hashes of secrets; prefer fingerprints of public data
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Union, Iterable, Optional

BytesLike = Union[bytes, bytearray, memoryview]
DataLike = Union[str, BytesLike]

__all__ = [
    "sha3_256",
    "sha3_512",
    "sha512",
    "fingerprint",
    "ct_equal",
    "to_hex",
    "from_hex",
    "to_b64",
    "from_b64",
    "concat_bytes",
]


# ---------- internal helpers ----------

def _to_bytes(data: DataLike, *, encoding: str = "utf-8") -> bytes:
    """Normalize input to bytes. Accepts bytes/bytearray/memoryview/str."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode(encoding)
    raise TypeError("data must be bytes, bytearray, memoryview, or str")


def _require_bytes(name: str, value: BytesLike) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


# ---------- hashing primitives ----------

def sha3_256(data: DataLike) -> bytes:
    """Return SHA3-256 digest of input as raw bytes."""
    return hashlib.sha3_256(_to_bytes(data)).digest()


def sha3_512(data: DataLike) -> bytes:
    """Return SHA3-512 digest of input as raw bytes."""
    return hashlib.sha3_512(_to_bytes(data)).digest()


def sha512(data: DataLike) -> bytes:
    """Return SHA-512 digest of input as raw bytes."""
    return hashlib.sha512(_to_bytes(data)).digest()


# ---------- fingerprints & equality ----------

def fingerprint(data: BytesLike, size: int = 8) -> str:
    """
    Produce a short, stable hex fingerprint for bytes-like input.

    Args:
        data: bytes-like value to fingerprint (e.g., a public key)
        size: number of bytes from the SHA3-256 digest to include (default 8)

    Returns:
        Lowercase hex string of length 2*size.

    Notes:
        - This is NOT a MAC; it’s intended for non-secret identifiers,
          UI display, logging key IDs, etc.
        - For UI, 8–16 bytes (16–32 hex chars) is a good range.
    """
    raw = _require_bytes("data", data)
    if not isinstance(size, int) or size <= 0:
        raise ValueError("size must be a positive integer")
    digest = sha3_256(raw)
    if size > len(digest):
        raise ValueError(f"size cannot exceed digest length ({len(digest)})")
    return digest[:size].hex()


def ct_equal(a: BytesLike, b: BytesLike) -> bool:
    """
    Constant-time equality comparison for two bytes-like inputs.

    Returns:
        True if equal, False otherwise.
    """
    return hmac.compare_digest(_require_bytes("a", a), _require_bytes("b", b))


# ---------- encoding helpers (optional but handy) ----------

def to_hex(data: BytesLike) -> str:
    """Encode bytes-like to lowercase hex string."""
    return _require_bytes("data", data).hex()


def from_hex(hex_str: str) -> bytes:
    """Decode lowercase/uppercase hex string to bytes."""
    if not isinstance(hex_str, str):
        raise TypeError("hex_str must be a str")
    try:
        return binascii.unhexlify(hex_str.strip())
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid hex string") from e


def to_b64(data: BytesLike) -> str:
    """Encode bytes-like to URL-safe Base64 string without padding."""
    raw = _require_bytes("data", data)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def from_b64(b64_str: str) -> bytes:
    """Decode URL-safe Base64 string (with or without padding) to bytes."""
    if not isinstance(b64_str, str):
        raise TypeError("b64_str must be a str")
    s = b64_str.strip().encode("ascii")
    # Restore padding if missing
    pad = (-len(s)) % 4
    s += b"=" * pad
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base64 string") from e


def concat_bytes(parts: Iterable[BytesLike]) -> bytes:
    """Safely concatenate an iterable of bytes-like parts into one bytes object."""
    out = bytearray()
    for i, p in enumerate(parts):
        if not isinstance(p, (bytes, bytearray, memoryview)):
            raise TypeError(f"part {i} is not bytes-like")
        out += p
    return bytes(out)


# ---------- basic self-tests (optional) ----------

def _self_test() -> None:
    # Hash determinism and known behavior
    assert sha3_256(b"") == hashlib.sha3_256(b"").digest()
    assert sha3_512(b"abc") == hashlib.sha3_512(b"abc").digest()
    assert sha512("abc") == hashlib.sha512(b"abc").digest()

    # Fingerprint length & determinism
    fp8 = fingerprint(b"hello", 8)
    fp12 = fingerprint(b"hello", 12)
    assert len(fp8) == 16 and len(fp12) == 24
    assert fp8 == fingerprint(b"hello", 8)

    # Constant-time equality
    assert ct_equal(b"\x00\x01", b"\x00\x01") is True
    assert ct_equal(b"\x00\x01", b"\x00\x02") is False

    # Hex/Base64 helpers
    hx = to_hex(b"\x00\xff")
    assert hx == "00ff" and from_hex(hx) == b"\x00\xff"

    b64 = to_b64(b"\x00\xff")
    assert from_b64(b64) == b"\x00\xff"

    # Concat
    assert concat_bytes([b"a", b"b", b"c"]) == b"abc"

    print("hash_utils.py self-test: OK")


if __name__ == "__main__":
    _self_test()