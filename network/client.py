# network/client.py
"""
QSMS network client.
Handles:
  - Authentication via AuthClient
  - Kyber KEM key exchange
  - Encrypted send/receive of messages
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

from .message_protocol import Message, MessageHeader, MessageType
from .auth_protocol import AuthClient, AuthStage, is_auth_message
from Backend.crypto_manager import CryptoManager

_LEN_PACK = "!I"
_NLEN_PACK = "!H"


def _write_frame(sock: socket.socket, payload: bytes):
    sock.sendall(struct.pack(_LEN_PACK, len(payload)) + payload)


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(sock: socket.socket):
    hdr = _read_exact(sock, 4)
    (n,) = struct.unpack(_LEN_PACK, hdr)
    return _read_exact(sock, n)


import base64
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass
class QSMSClient:
    host: str = "127.0.0.1"
    port: int = 5000

    conn: Optional[socket.socket] = None
    crypto: Optional[CryptoManager] = None

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        self.conn = sock
        print(f"[+] Connected to QSMS server at {self.host}:{self.port}")

    def authenticate(self, username, password):
        ac = AuthClient(username, password)

        init_msg = ac.start()
        _write_frame(self.conn, init_msg.to_bytes())

        chal_raw = _read_frame(self.conn)
        chal = Message.from_bytes(chal_raw)

        resp = ac.respond(chal)
        _write_frame(self.conn, resp.to_bytes())

        res_raw = _read_frame(self.conn)
        res = Message.from_bytes(res_raw)

        ok, uid = ac.parse_result(res)

        if not ok:
            raise PermissionError("Authentication failed")

        print(f"[+] Authenticated as '{username}' (user_id={uid})")

    def key_exchange(self):
        raw1 = _read_frame(self.conn)
        msg1 = Message.from_bytes(raw1)

        server_pk = _b64d(msg1.meta["server_pk_b64"])

        cm = CryptoManager()
        kem_ct, _ = cm.encapsulate(server_pk)

        msg2 = Message(
            header=MessageHeader.new(
                MessageType.KEY_UPDATE,
                payload_len=0,
                meta_len=0,
            ),
            payload=b"",
            meta={
                "kx": "client_ct",
                "ct_b64": _b64e(kem_ct),
            },
        )
        _write_frame(self.conn, msg2.to_bytes())

        ok_raw = _read_frame(self.conn)
        ok_msg = Message.from_bytes(ok_raw)

        if ok_msg.meta["kx"] != "ok":
            raise RuntimeError("KEM handshake failed")

        self.crypto = cm
        print("[+] Handshake complete")

    def _send_encrypted(self, plaintext: bytes):
        nonce, ct = self.crypto.encrypt(plaintext, aad=None)
        body = struct.pack(_NLEN_PACK, len(nonce)) + nonce + ct
        _write_frame(self.conn, body)

    def _recv_encrypted(self):
        body = _read_frame(self.conn)
        (nlen,) = struct.unpack(_NLEN_PACK, body[:2])
        nonce = body[2 : 2 + nlen]
        ct = body[2 + nlen :]
        return self.crypto.decrypt(nonce, ct, aad=None)

    def send_text(self, txt: str, *, from_id: Optional[str] = None, to_id: Optional[str] = None):
        payload = txt.encode("utf-8")
        meta = {"ts": None}
        if from_id:
            meta["from"] = from_id
        if to_id:
            meta["to"] = to_id
        msg = Message(
            header=MessageHeader.new(
                MessageType.TEXT,
                payload_len=len(payload),
                meta_len=0,
            ),
            payload=payload,
            meta=meta,
        )
        self._send_encrypted(msg.to_bytes())


    def recv_message(self):
        try:
            raw = self._recv_encrypted()
            return Message.from_bytes(raw)
        except Exception:
            return None

    def close(self):
        try:
            if self.crypto:
                self.crypto.close()
        except:
            pass
        try:
            if self.conn:
                self.conn.close()
        except:
            pass
        print("[+] Client closed")
