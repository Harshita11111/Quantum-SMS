# qsms/network/server.py
"""
QSMS TCP server.

Implements the same framing and handshake as QSMSClient:

  1) Length-prefixed frames over TCP:
       [len: u32][frame-bytes]
  2) Authentication using auth_protocol.AuthServer:
       C->S AUTH_INIT
       S->C AUTH_CHALLENGE
       C->S AUTH_RESPONSE
       S->C AUTH_RESULT
  3) Key exchange using CryptoManager (Kyber + AES-GCM):
       S->C KEY_UPDATE { kx: "server_pk", server_pk_b64: ... }
       C->S KEY_UPDATE { kx: "client_ct", ct_b64: ... }
       S->C KEY_UPDATE { kx: "ok" }
  4) Encrypted TEXT messages (simple echo server for now).

This file is self-contained and talks directly to sockets so the
web UI can authenticate against DBUserStore users.
"""

from __future__ import annotations

import base64
import socket
import struct
import threading
from typing import Tuple

from qsms.network.message_protocol import Message, MessageHeader, MessageType
from qsms.network.auth_protocol import AuthServer, AuthStage, is_auth_message
from qsms.crypto_manager import CryptoManager
from qsms.database.user_management import DBUserStore

_LEN_PACK = "!I"   # outer frame length (u32)
_NLEN_PACK = "!H"  # nonce length in encrypted frames (u16)


# --------------------------- helpers -----------------------------------


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


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


def _send_encrypted(cm: CryptoManager, conn: socket.socket, plaintext: bytes) -> None:
    nonce, ciphertext = cm.encrypt(plaintext, aad=None)
    body = struct.pack(_NLEN_PACK, len(nonce)) + nonce + ciphertext
    _write_frame(conn, body)


def _recv_encrypted(cm: CryptoManager, conn: socket.socket) -> bytes:
    body = _read_frame(conn)
    if len(body) < 2:
        raise ValueError("encrypted frame too short")
    (nlen,) = struct.unpack(_NLEN_PACK, body[:2])
    if len(body) < 2 + nlen:
        raise ValueError("encrypted frame missing nonce")
    nonce = body[2:2 + nlen]
    ciphertext = body[2 + nlen:]
    return cm.decrypt(nonce, ciphertext, aad=None)


# ------------------------- per-client handler --------------------------


def handle_client(conn: socket.socket, addr: Tuple[str, int], auth_server: AuthServer) -> None:
    ip, port = addr
    print(f"[+] New connection from {ip}:{port}")

    try:
        # ---- AUTH_INIT ----
        init_bytes = _read_frame(conn)
        init_msg = Message.from_bytes(init_bytes)
        if not is_auth_message(init_msg, stage=AuthStage.INIT):
            raise RuntimeError("expected AUTH_INIT from client")

        username = (init_msg.meta or {}).get("username", "")
        client_nonce = (init_msg.meta or {}).get("client_nonce", "")
        print(f"[auth] INIT from username={username!r}")

        # ---- AUTH_CHALLENGE ----
        chal = auth_server.handle_init(username, client_nonce)
        _write_frame(conn, chal.to_bytes())

        # ---- AUTH_RESPONSE ----
        resp_bytes = _read_frame(conn)
        resp = Message.from_bytes(resp_bytes)
        if not is_auth_message(resp, stage=AuthStage.RESPONSE):
            raise RuntimeError("expected AUTH_RESPONSE from client")

        resp_meta = resp.meta or {}
        proof = resp_meta["proof"]
        client_nonce2 = resp_meta["client_nonce"]
        server_nonce = (chal.meta or {})["server_nonce"]

        # ---- AUTH_RESULT ----
        result = auth_server.handle_response(
            username=username,
            client_nonce_b64=client_nonce2,
            proof_b64=proof,
            server_nonce_b64=server_nonce,
        )
        _write_frame(conn, result.to_bytes())

        ok = bool((result.meta or {}).get("ok"))
        if not ok:
            print(f"[auth] Authentication FAILED for {username!r}")
            return

        print(f"[auth] Authentication OK for {username!r}")

        # ----------------- Key exchange -----------------
        cm = CryptoManager()
        server_pk = cm.generate_keys()

        # S -> C: server public key
        msg1 = Message(
            header=MessageHeader.new(MessageType.KEY_UPDATE, payload_len=0, meta_len=0),
            payload=b"",
            meta={"kx": "server_pk", "server_pk_b64": _b64e(server_pk)},
        )
        _write_frame(conn, msg1.to_bytes())

        # C -> S: client ciphertext
        msg2 = Message.from_bytes(_read_frame(conn))
        if msg2.header.msg_type != MessageType.KEY_UPDATE or (msg2.meta or {}).get("kx") != "client_ct":
            raise RuntimeError("expected KEY_UPDATE/client_ct from client")
        ct = _b64d((msg2.meta or {})["ct_b64"])

        cm.decapsulate(ct)  # derives AES keys

        # S -> C: OK
        msg_ok = Message(
            header=MessageHeader.new(MessageType.KEY_UPDATE, payload_len=0, meta_len=0),
            payload=b"",
            meta={"kx": "ok"},
        )
        _write_frame(conn, msg_ok.to_bytes())

        print(f"[kx] Key exchange complete with {username!r}")

        # ----------------- Encrypted chat loop -----------------
        while True:
            try:
                plaintext = _recv_encrypted(cm, conn)
            except ConnectionError:
                print(f"[conn] {ip}:{port} closed connection")
                break
            except Exception as e:
                print(f"[!] decrypt error from {username!r}: {e}")
                break

            try:
                msg = Message.from_bytes(plaintext)
            except Exception as e:
                print(f"[!] invalid message from {username!r}: {e}")
                continue

            if msg.header.msg_type == MessageType.TEXT:
                text = msg.payload.decode("utf-8", errors="replace").rstrip()
                print(f"[msg] {username}: {text}")
                # simple echo
                _send_encrypted(cm, conn, plaintext)
            else:
                print(f"[msg] {username}: non-TEXT message type={msg.header.msg_type}")

    except Exception as e:
        print(f"[!] Error handling {ip}:{port}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[+] Connection from {ip}:{port} closed")


# ----------------------------- main loop -------------------------------


def main(host: str = "0.0.0.0", port: int = 5000) -> None:
    user_store = DBUserStore()
    auth_server = AuthServer(user_store)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)

    print(f"[+] QSMS server listening on {host}:{port}")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, auth_server),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[+] KeyboardInterrupt – shutting down server.")
    finally:
        srv.close()


if __name__ == "__main__":
    # Ensure demo user 'alice' exists in the DB for testing
    store = DBUserStore()
    try:
        store.add_user("alice", "correct horse battery staple")
        print("[+] Demo user 'alice' bootstrapped in DB.")
    except ValueError:
        print("[+] Demo user 'alice' already existed in DB.")

    main(host="127.0.0.1", port=5000)
