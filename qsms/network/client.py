# qsms/network/client.py
"""
QSMS network client.

Connects to a QSMS server, runs:
  1) Authentication (auth_protocol.AuthClient)
  2) KEM-based key exchange (crypto_manager.CryptoManager)
and then sends/receives encrypted QSMS Messages over a length-prefixed TCP
transport.

Transport framing (matches server/connection_handler.py):
  [len: u32][frame-bytes]
Post-handshake encrypted frame bytes:
  [nonce_len: u16][nonce ...][ciphertext ...]
Where the plaintext inside AES-GCM is a serialized QSMS Message
(i.e., Message.to_bytes()).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

from .message_protocol import Message, MessageHeader, MessageType
from .auth_protocol import AuthClient, AuthStage, is_auth_message
from ..crypto_manager import CryptoManager

_LEN_PACK = "!I"   # outer frame length
_NLEN_PACK = "!H"  # nonce length


# -------------------- tiny helpers --------------------

def _b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode("ascii"))

def _safe_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return "<non-utf8>"

def _write_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(_LEN_PACK, len(payload)) + payload)

def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed during recv")
        buf.extend(chunk)
    return bytes(buf)

def _read_frame(sock: socket.socket, *, max_len: int = 16 * 1024 * 1024) -> bytes:
    hdr = _read_exact(sock, 4)
    (length,) = struct.unpack(_LEN_PACK, hdr)
    if length > max_len:
        raise ValueError(f"frame too large: {length} > {max_len}")
    return _read_exact(sock, length)


# -------------------- client --------------------

@dataclass
class QSMSClient:
    host: str = "127.0.0.1"
    port: int = 5000

    conn: Optional[socket.socket] = None
    crypto: Optional[CryptoManager] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # ----------- Connection management -----------

    def connect(self) -> None:
        if self.conn is not None:
            raise RuntimeError("Client already connected")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        self.conn = sock
        print(f"[+] Connected to QSMS server at {self.host}:{self.port}")

        # crypto context created after KX
        self.crypto = None

    # ----------- Authentication -----------

    def authenticate(self, username: str, password: str) -> None:
        """
        Client side of the auth handshake:
          C->S AUTH_INIT
          S->C AUTH_CHALLENGE
          C->S AUTH_RESPONSE
          S->C AUTH_RESULT (ok)
        """
        if self.conn is None:
            raise RuntimeError("connect() first")

        self.username = username
        self.password = password

        ac = AuthClient(username, password)

        # C -> S: INIT
        init_msg = ac.start()
        _write_frame(self.conn, init_msg.to_bytes())

        # S -> C: CHALLENGE
        chal_bytes = _read_frame(self.conn)
        chal = Message.from_bytes(chal_bytes)
        if not is_auth_message(chal, stage=AuthStage.CHALLENGE):
            raise RuntimeError("server did not send AUTH_CHALLENGE")

        # C -> S: RESPONSE
        resp = ac.respond(chal)
        _write_frame(self.conn, resp.to_bytes())

        # S -> C: RESULT
        res_bytes = _read_frame(self.conn)
        res = Message.from_bytes(res_bytes)
        ok, token = ac.parse_result(res)
        if not ok:
            raise PermissionError("authentication failed")
        print(f"[+] Authenticated as '{username}'. token={bool(token)}")

    # ----------- Key Exchange -----------

    def key_exchange(self) -> None:
        """
        Mirrors the server-side sequence:
          S -> C: KEY_UPDATE { kx: "server_pk", server_pk_b64 }
          C -> S: KEY_UPDATE { kx: "client_ct", ct_b64 }
          S -> C: KEY_UPDATE { kx: "ok" }
        """
        if self.conn is None:
            raise RuntimeError("connect() first")

        # S -> C: server pk
        msg1 = Message.from_bytes(_read_frame(self.conn))
        if msg1.header.msg_type != MessageType.KEY_UPDATE or (msg1.meta or {}).get("kx") != "server_pk":
            raise RuntimeError("expected server public key (KEY_UPDATE/server_pk)")

        server_pk = _b64d((msg1.meta or {})["server_pk_b64"])

        # Create CryptoManager and encapsulate
        cm = CryptoManager()
        kem_ct, _shared = cm.encapsulate(server_pk)

        # C -> S: send client ciphertext
        msg2 = Message(
            header=MessageHeader.new(MessageType.KEY_UPDATE, payload_len=0, meta_len=0),
            payload=b"",
            meta={"kx": "client_ct", "ct_b64": _b64e(kem_ct)},
        )
        _write_frame(self.conn, msg2.to_bytes())

        # S -> C: ok
        msg_ok = Message.from_bytes(_read_frame(self.conn))
        if msg_ok.header.msg_type != MessageType.KEY_UPDATE or (msg_ok.meta or {}).get("kx") != "ok":
            raise RuntimeError("key exchange did not complete")

        self.crypto = cm
        print(
            f"[+] Handshake complete (role={self.crypto.role}, "
            f"aad={self.crypto.aad.hex()[:16]}...)"
        )

    # ----------- Encrypted send/receive of QSMS Messages -----------

    def _send_encrypted_bytes(self, plaintext: bytes) -> None:
        if self.conn is None or self.crypto is None:
            raise RuntimeError("handshake not complete")
        nonce, ciphertext = self.crypto.encrypt(plaintext, aad=None)
        body = struct.pack(_NLEN_PACK, len(nonce)) + nonce + ciphertext
        _write_frame(self.conn, body)

    def _recv_encrypted_bytes(self) -> bytes:
        if self.conn is None or self.crypto is None:
            raise RuntimeError("handshake not complete")
        body = _read_frame(self.conn)
        if len(body) < 2:
            raise ValueError("encrypted frame too short")
        (nlen,) = struct.unpack(_NLEN_PACK, body[:2])
        if len(body) < 2 + nlen:
            raise ValueError("encrypted frame missing nonce")
        nonce = body[2:2 + nlen]
        ciphertext = body[2 + nlen:]
        return self.crypto.decrypt(nonce, ciphertext, aad=None)

    def send_message(self, msg: Message) -> None:
        self._send_encrypted_bytes(msg.to_bytes())

    def recv_message(self) -> Optional[Message]:
        try:
            raw = self._recv_encrypted_bytes()
        except Exception as e:
            print(f"[!] receive error: {e}")
            return None
        try:
            return Message.from_bytes(raw)
        except Exception as e:
            print(f"[!] invalid message: {e}")
            return None

    # Convenience for TEXT messages
    def send_text(self, text: str) -> None:
        payload = text.encode("utf-8")
        msg = Message(
            header=MessageHeader.new(MessageType.TEXT, payload_len=len(payload), meta_len=0),
            payload=payload,
            meta={"ts": None},
        )
        self.send_message(msg)

    # ----------- Interactive loop -----------

    def interactive_loop(self) -> None:
        print("[+] Enter messages to send. Type 'quit' to exit.\n")
        while True:
            try:
                text = input("> ")
            except EOFError:
                text = "quit"

            msg = text.strip()
            if not msg:
                continue

            try:
                self.send_text(text)
            except Exception as e:
                print(f"[!] Error sending: {e}")
                break

            if msg.lower() == "quit":
                print("[+] Sent 'quit' – closing connection.")
                break

            reply = self.recv_message()
            if reply is None:
                print("[+] Server closed the connection.")
                break

            if reply.header.msg_type == MessageType.TEXT:
                print(f"< {_safe_utf8(reply.payload).rstrip()}")
            else:
                print(f"< [type={reply.header.msg_type}] {len(reply.payload)} bytes")

        self.close()

    # ----------- Cleanup -----------

    def close(self) -> None:
        if self.crypto is not None:
            try:
                self.crypto.close()
            except Exception:
                pass
            self.crypto = None

        if self.conn is not None:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

        print("[+] Client closed.")


# -------------------- demo runner --------------------

if __name__ == "__main__":
    """
    Demo client.

    1) Run the server from project root:

        python -m qsms.network.server

    2) Then start this client:

        python -m qsms.network.client
    """
    c = QSMSClient(host="127.0.0.1", port=5000)
    try:
        c.connect()
        # demo creds — must exist on server's UserStore
        c.authenticate("alice", "correct horse battery staple")
        c.key_exchange()
        c.interactive_loop()
    except KeyboardInterrupt:
        print("\n[+] KeyboardInterrupt, closing client.")
        c.close()
    except Exception as e:
        print(f"[!] Fatal error in client: {e}")
        c.close()
