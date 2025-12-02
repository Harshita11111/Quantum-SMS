# network/connection_handler.py
from __future__ import annotations

import asyncio
import struct
import time
import traceback
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Awaitable

from .message_protocol import Message, MessageHeader, MessageType
from .auth_protocol import AuthServer, AuthStage, is_auth_message
from Backend.crypto_manager import CryptoManager

_LEN_PACK = "!I"
_NLEN_PACK = "!H"


@dataclass
class PeerInfo:
    addr: str
    port: int
    connected_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))


@dataclass
class Connection:
    id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    peer: PeerInfo
    username: Optional[str] = None
    is_authenticated: bool = False
    session: dict = field(default_factory=dict)

    def close(self):
        try:
            self.writer.close()
        except:
            pass


async def _read_frame(reader: asyncio.StreamReader, *, max_len=16 * 1024 * 1024):
    hdr = await reader.readexactly(4)
    (n,) = struct.unpack(_LEN_PACK, hdr)
    if n > max_len:
        raise ValueError(f"Frame too large {n}")
    return await reader.readexactly(n)


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes):
    writer.write(struct.pack(_LEN_PACK, len(payload)))
    writer.write(payload)
    await writer.drain()


async def _read_app_bytes(conn: Connection, max_len: int):
    data = await _read_frame(conn.reader, max_len=max_len)
    cm: Optional[CryptoManager] = conn.session.get("crypto")
    if not cm:
        return data

    if len(data) < 2:
        raise ValueError("Encrypted frame too short")

    (nlen,) = struct.unpack(_NLEN_PACK, data[:2])
    nonce = data[2 : 2 + nlen]
    ciphertext = data[2 + nlen :]
    return cm.decrypt(nonce, ciphertext, aad=None)


async def _write_app_bytes(conn: Connection, plaintext: bytes):
    cm: Optional[CryptoManager] = conn.session.get("crypto")
    if not cm:
        return await _write_frame(conn.writer, plaintext)

    nonce, ciphertext = cm.encrypt(plaintext, aad=None)
    framed = struct.pack(_NLEN_PACK, len(nonce)) + nonce + ciphertext
    await _write_frame(conn.writer, framed)


async def send_message(conn: Connection, msg: Message):
    await _write_app_bytes(conn, msg.to_bytes())


class ConnectionHandler:
    def __init__(
        self,
        auth_server: AuthServer,
        *,
        crypto_manager_factory: Optional[Callable[[], CryptoManager]] = None,
        on_authenticated=None,
        on_message=None,
        on_disconnect=None,
        max_message_size=16 * 1024 * 1024,
    ):
        self.auth_server = auth_server
        self.crypto_manager_factory = crypto_manager_factory or (lambda: CryptoManager())
        self.on_authenticated = on_authenticated
        self.on_message = on_message
        self.on_disconnect = on_disconnect
        self.max_message_size = max_message_size

        self._srv = None
        self._next_conn_id = 1
        self._connections = {}

    async def start(self, host, port):
        self._srv = await asyncio.start_server(self._handle_client, host, port)

    async def serve_forever(self):
        async with self._srv:
            await self._srv.serve_forever()

    async def shutdown(self):
        for c in list(self._connections.values()):
            c.close()
        if self._srv:
            self._srv.close()
            await self._srv.wait_closed()

    async def _handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        addr, port = peer if isinstance(peer, tuple) else ("?", 0)

        conn_id = self._next_conn_id
        self._next_conn_id += 1

        conn = Connection(
            id=conn_id, reader=reader, writer=writer, peer=PeerInfo(addr, port)
        )
        self._connections[conn_id] = conn

        try:
            await self._authenticate(conn)
            if conn.is_authenticated:
                await self._key_exchange(conn)
                if self.on_authenticated:
                    await self.on_authenticated(conn)

            while True:
                raw = await _read_app_bytes(conn, self.max_message_size)
                msg = Message.from_bytes(raw)

                if not conn.is_authenticated and msg.header.msg_type != MessageType.AUTH:
                    continue

                if self.on_message:
                    await self.on_message(conn, msg)
                else:
                    if msg.header.msg_type == MessageType.TEXT:
                        await send_message(conn, msg)

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            traceback.print_exc()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

            self._connections.pop(conn_id, None)
            if self.on_disconnect:
                try:
                    await self.on_disconnect(conn)
                except:
                    pass

    # ---------------- AUTH ----------------
    async def _authenticate(self, conn: Connection):
        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        msg = Message.from_bytes(raw)

        if not is_auth_message(msg, AuthStage.INIT):
            return

        username = msg.meta.get("username", "")
        client_nonce_b64 = msg.meta.get("client_nonce", "")
        conn.username = username

        chal = self.auth_server.handle_init(username, client_nonce_b64)
        await _write_frame(conn.writer, chal.to_bytes())

        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        resp = Message.from_bytes(raw)

        if not is_auth_message(resp, AuthStage.RESPONSE):
            return

        password = resp.meta.get("password", "")

        res = self.auth_server.handle_response(
            username=resp.meta.get("username", username),
            password=password,
            client_nonce_b64=resp.meta.get("client_nonce", ""),
            server_nonce_b64=chal.meta.get("server_nonce", ""),
        )

        await _write_frame(conn.writer, res.to_bytes())
        conn.is_authenticated = bool(res.meta.get("ok"))

        if conn.is_authenticated:
            conn.session["user_id"] = res.meta.get("user_id")

    # ---------------- KEM Key Exchange ----------------
    async def _key_exchange(self, conn: Connection):
        cm = self.crypto_manager_factory()
        server_pk = cm.generate_keys()

        msg1 = Message(
            header=MessageHeader.new(
                MessageType.KEY_UPDATE,
                payload_len=0,
                meta_len=0,
            ),
            payload=b"",
            meta={
                "kx": "server_pk",
                "alg": cm.algorithm,
                "server_pk_b64": _b64e(server_pk),
            },
        )

        await _write_frame(conn.writer, msg1.to_bytes())

        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        msg2 = Message.from_bytes(raw)

        if (msg2.meta or {}).get("kx") != "client_ct":
            return

        ct = _b64d(msg2.meta.get("ct_b64", ""))
        cm.decapsulate(ct)

        conn.session["crypto"] = cm

        ok_msg = Message(
            header=MessageHeader.new(
                MessageType.KEY_UPDATE,
                payload_len=0,
                meta_len=0,
            ),
            payload=b"",
            meta={"kx": "ok"},
        )
        await _write_frame(conn.writer, ok_msg.to_bytes())


import base64
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)
