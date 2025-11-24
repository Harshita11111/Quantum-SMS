"""
message_protocol.py

QSMS Message Protocol

This module defines the *plaintext* message format used inside the
Quantum-Safe Messaging (QSMS) system.  It does NOT do any networking
or key exchange by itself; it only knows how to:

    - represent a message (header + payload + optional metadata),
    - serialize that message into bytes,
    - parse bytes back into a structured message.

Encryption is performed by higher layers (e.g. a CryptoManager) by
taking the serialized bytes and feeding them into AES-GCM.  A typical
stack therefore looks like:

    Message -> serialize() -> plaintext bytes
            -> AES-GCM with directional key + AAD
            -> nonce || ciphertext
            -> framed on the wire (length prefix at TCP layer)

On receive:

    frame -> nonce || ciphertext
          -> AES-GCM decrypt with same key + AAD -> plaintext bytes
          -> parse() -> Message instance

The protocol is versioned and binary, with a fixed-length header
followed by optional JSON metadata and then the raw payload.
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 4-byte magic constant used to recognise QSMS messages on the wire.
MAGIC = b"QSM1"

# Protocol version (1 byte).  Increment if you ever change the layout.
PROTOCOL_VERSION = 1

# Maximum size of a single message (metadata + payload) in bytes.
# This is a safety limit; transport framing may impose a stricter one.
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MiB


# Binary header layout (network byte order / big-endian):
#
#   0  -  3 : magic        (4s)   = b"QSM1"
#   4  :      version      (B)    = 1
#   5  :      msg_type     (B)    = enum MessageType
#   6  -  7 : flags        (H)    = bit flags for future use
#   8  - 15 : timestamp_ms (Q)    = UNIX epoch in milliseconds
#  16  - 23 : msg_id       (Q)    = random 64-bit identifier
#  24  - 27: payload_len   (I)    = length of payload in bytes
#  28  - 29: meta_len      (H)    = length of metadata JSON in bytes
#
# Total fixed header size: 30 bytes.
#
# After the header come:
#     - meta_len bytes of UTF-8 JSON (may be empty)
#     - payload_len bytes of raw payload
#
_HEADER_STRUCT = struct.Struct("!4sBBHQQIH")
HEADER_SIZE = _HEADER_STRUCT.size  # should be 30


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

class MessageType(IntEnum):
    """
    Logical message types used by the QSMS application layer.

    These are suggestions; you can extend or repurpose them as your
    project grows.  The `OTHER` type is provided for experimentation.
    """
    TEXT = 0           # human-readable chat message
    AUTH = 1           # authentication / login / token exchange
    SYSTEM = 2         # system notifications, errors, control
    FILE_CHUNK = 3     # chunk of a larger file transfer
    PING = 4           # keep-alive or latency measurement
    PONG = 5           # response to PING
    KEY_UPDATE = 6     # rekey / key rotation signalling
    OTHER = 255        # catch-all / experimental


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MessageHeader:
    """
    Represents the fixed-size header of a QSMS message.

    Most application code does not need to construct this directly;
    the Message helper methods will do it for you.
    """
    version: int
    msg_type: MessageType
    flags: int
    timestamp_ms: int
    msg_id: int
    payload_len: int
    meta_len: int

    @classmethod
    def new(
        cls,
        msg_type: MessageType,
        *,
        flags: int = 0,
        timestamp_ms: Optional[int] = None,
        msg_id: Optional[int] = None,
        payload_len: int = 0,
        meta_len: int = 0,
    ) -> "MessageHeader":
        if timestamp_ms is None:
            # milliseconds since UNIX epoch
            timestamp_ms = int(time.time() * 1000)
        if msg_id is None:
            # 64 bits of randomness; collisions are extremely unlikely
            msg_id = int.from_bytes(os.urandom(8), "big")

        return cls(
            version=PROTOCOL_VERSION,
            msg_type=msg_type,
            flags=flags,
            timestamp_ms=timestamp_ms,
            msg_id=msg_id,
            payload_len=payload_len,
            meta_len=meta_len,
        )


@dataclass
class Message:
    """
    High-level representation of a QSMS message.

    Fields:
        header:  MessageHeader instance describing this message.
        payload: Raw bytes (already compressed, encoded, etc. as needed).
        meta:    Optional dictionary with metadata, encoded as JSON.
                 Typical fields might include:
                    - "from": user identifier
                    - "to": recipient identifier
                    - "content_type": e.g. "text/plain"
                    - "filename": for file transfers
    """
    header: MessageHeader
    payload: bytes
    meta: Dict[str, Any]

    # ------------- Convenience constructors -------------

    @classmethod
    def text(
        cls,
        text: str,
        *,
        from_id: Optional[str] = None,
        to_id: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
        encoding: str = "utf-8",
    ) -> "Message":
        """Build a TEXT message from a Unicode string."""
        payload = text.encode(encoding)
        meta: Dict[str, Any] = {
            "content_type": f"text/{encoding}",
        }
        if from_id is not None:
            meta["from"] = from_id
        if to_id is not None:
            meta["to"] = to_id
        if extra_meta:
            meta.update(extra_meta)

        # header will be completed in serialize()
        header = MessageHeader.new(MessageType.TEXT, payload_len=len(payload), meta_len=0)
        # meta_len will be corrected by serialize_message()
        return cls(header=header, payload=payload, meta=meta)

    # ------------- Serialisation helpers -------------

    def to_bytes(self) -> bytes:
        """
        Serialise this message to bytes (header + metadata JSON + payload).

        This does NOT encrypt.  The result is suitable for feeding into
        AES-GCM via a CryptoManager or similar.
        """
        return serialize_message(self)

    @staticmethod
    def from_bytes(data: bytes) -> "Message":
        """Inverse of to_bytes()."""
        return parse_message(data)


# ---------------------------------------------------------------------------
# Serialisation / parsing
# ---------------------------------------------------------------------------

def serialize_message(msg: Message) -> bytes:
    """
    Convert a Message object into bytes according to the QSMS format.

    Layout:
        [HEADER (30 bytes)]
        [META JSON (meta_len bytes)]
        [PAYLOAD (payload_len bytes)]
    """
    # Encode metadata as compact JSON (or empty object if none)
    meta_dict = msg.meta or {}
    meta_bytes = json.dumps(meta_dict, separators=(",", ":")).encode("utf-8")
    payload = msg.payload or b""

    if len(meta_bytes) > 0xFFFF:
        raise ValueError("Metadata too large (must fit in 2 bytes length field)")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("Payload too large (must fit in 4 bytes length field)")

    total = len(meta_bytes) + len(payload)
    if total > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large ({total} > {MAX_MESSAGE_SIZE})")

    # Update header lengths
    header = msg.header
    header.meta_len = len(meta_bytes)
    header.payload_len = len(payload)

    # Pack header
    header_bytes = _HEADER_STRUCT.pack(
        MAGIC,
        header.version,
        int(header.msg_type),
        header.flags,
        header.timestamp_ms,
        header.msg_id,
        header.payload_len,
        header.meta_len,
    )

    return header_bytes + meta_bytes + payload


def parse_message(data: bytes) -> Message:
    """
    Parse bytes into a Message object.

    Raises ValueError if the data is malformed or the magic/version
    does not match expectations.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError("Data too short for QSMS header")

    magic, version, msg_type, flags, ts_ms, msg_id, payload_len, meta_len = _HEADER_STRUCT.unpack(
        data[:HEADER_SIZE]
    )

    if magic != MAGIC:
        raise ValueError(f"Invalid magic: expected {MAGIC!r}, got {magic!r}")

    if version != PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported protocol version {version}; "
            f"this library expects {PROTOCOL_VERSION}"
        )

    total_len = HEADER_SIZE + meta_len + payload_len
    if len(data) != total_len:
        raise ValueError(
            f"Inconsistent lengths: expected {total_len} bytes, got {len(data)} bytes"
        )

    meta_start = HEADER_SIZE
    meta_end = meta_start + meta_len
    payload_start = meta_end
    payload_end = payload_start + payload_len

    meta_bytes = data[meta_start:meta_end]
    payload = data[payload_start:payload_end]

    if meta_bytes:
        try:
            meta = json.loads(meta_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError("Invalid metadata JSON") from e
    else:
        meta = {}

    header = MessageHeader(
        version=version,
        msg_type=MessageType(msg_type),
        flags=flags,
        timestamp_ms=ts_ms,
        msg_id=msg_id,
        payload_len=payload_len,
        meta_len=meta_len,
    )

    return Message(header=header, payload=payload, meta=meta)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def build_ping(msg_id: Optional[int] = None) -> Message:
    """Construct a PING message (payload empty, msg_id may be reused in PONG)."""
    header = MessageHeader.new(
        MessageType.PING,
        msg_id=msg_id,
        payload_len=0,
        meta_len=0,
    )
    return Message(header=header, payload=b"", meta={})


def build_pong(request: Message) -> Message:
    """Construct a PONG corresponding to a given PING message."""
    header = MessageHeader.new(
        MessageType.PONG,
        msg_id=request.header.msg_id,
        payload_len=0,
        meta_len=0,
    )
    return Message(header=header, payload=b"", meta={})


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick round-trip test for manual debugging.
    print("[+] QSMS message_protocol self-test")

    msg = Message.text(
        "Hello from QSMS!",
        from_id="alice",
        to_id="bob",
        extra_meta={"room": "general"},
    )

    wire = msg.to_bytes()
    print(f"Serialized length: {len(wire)} bytes (header={HEADER_SIZE})")

    parsed = Message.from_bytes(wire)
    print("Parsed header:", parsed.header)
    print("Parsed meta:", parsed.meta)
    print("Parsed payload:", parsed.payload.decode("utf-8"))

    assert parsed.payload == msg.payload
    assert parsed.meta == msg.meta
    assert parsed.header.msg_type == MessageType.TEXT

    print("[+] Self-test OK")
