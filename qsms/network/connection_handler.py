# qsms/network/connection_handler.py
from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Awaitable


from .message_protocol import Message, MessageHeader, MessageType
from .auth_protocol import AuthServer, AuthStage, is_auth_message
from ..crypto_manager import CryptoManager

_LEN_PACK = "!I"   # 4-byte big-endian unsigned length
_NLEN_PACK = "!H"  # 2-byte big-endian unsigned (nonce length)


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

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass


# ---------------- framing (plaintext) ----------------

async def _read_frame(reader: asyncio.StreamReader, *, max_len: int = 16 * 1024 * 1024) -> bytes:
    hdr = await reader.readexactly(4)
    (n,) = struct.unpack(_LEN_PACK, hdr)
    if n > max_len:
        raise ValueError(f"Frame too large: {n} > {max_len}")
    return await reader.readexactly(n)


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(struct.pack(_LEN_PACK, len(payload)))
    writer.write(payload)
    await writer.drain()


# ------------- framing (after encryption is active) -------------

async def _read_app_bytes(conn: Connection, max_len: int) -> bytes:
    data = await _read_frame(conn.reader, max_len=max_len)
    cm: Optional[CryptoManager] = conn.session.get("crypto")
    if not cm:
        return data
    if len(data) < 2:
        raise ValueError("Encrypted frame too short")
    (nlen,) = struct.unpack(_NLEN_PACK, data[:2])
    if len(data) < 2 + nlen:
        raise ValueError("Encrypted frame missing nonce")
    nonce = data[2:2 + nlen]
    ciphertext = data[2 + nlen:]
    return cm.decrypt(nonce, ciphertext, aad=None)

async def _write_app_bytes(conn: Connection, plaintext: bytes) -> None:
    cm: Optional[CryptoManager] = conn.session.get("crypto")
    if not cm:
        await _write_frame(conn.writer, plaintext)
        return
    nonce, ciphertext = cm.encrypt(plaintext, aad=None)
    framed = struct.pack(_NLEN_PACK, len(nonce)) + nonce + ciphertext
    await _write_frame(conn.writer, framed)

async def send_message(conn: Connection, msg: Message) -> None:
    await _write_app_bytes(conn, msg.to_bytes())


# ---------------- main server ----------------

class ConnectionHandler:
    def __init__(
        self,
        auth_server: AuthServer,
        *,
        crypto_manager_factory: Optional[Callable[[], CryptoManager]] = None,
        on_authenticated: Optional[Callable[[Connection], Awaitable[None]]] = None,
        on_message: Optional[Callable[[Connection, Message], Awaitable[None]]] = None,
        on_disconnect: Optional[Callable[[Connection], Awaitable[None]]] = None,
        max_message_size: int = 16 * 1024 * 1024,
    ) -> None:
        self.auth_server = auth_server
        self.crypto_manager_factory = crypto_manager_factory or (lambda: CryptoManager())
        self.on_authenticated = on_authenticated
        self.on_message = on_message
        self.on_disconnect = on_disconnect
        self.max_message_size = max_message_size

        self._srv: Optional[asyncio.AbstractServer] = None
        self._next_conn_id = 1
        self._connections: Dict[int, Connection] = {}

    async def start(self, host: str, port: int) -> None:
        self._srv = await asyncio.start_server(self._handle_client, host, port)

    async def serve_forever(self) -> None:
        if self._srv is None:
            raise RuntimeError("Server not started. Call start() first.")
        async with self._srv:
            await self._srv.serve_forever()

    async def shutdown(self) -> None:
        for c in list(self._connections.values()):
            c.close()
        if self._srv is not None:
            self._srv.close()
            await self._srv.wait_closed()

    def list_connections(self) -> Dict[int, Connection]:
        return dict(self._connections)

    def get_connection(self, conn_id: int) -> Optional[Connection]:
        return self._connections.get(conn_id)

    async def send_to(self, conn_id: int, msg: Message) -> bool:
        c = self._connections.get(conn_id)
        if not c:
            return False
        await send_message(c, msg)
        return True

    async def broadcast(self, msg: Message, *, only_authenticated: bool = True) -> None:
        tasks = []
        for c in self._connections.values():
            if only_authenticated and not c.is_authenticated:
                continue
            tasks.append(send_message(c, msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        addr, port = (peer[0], peer[1]) if isinstance(peer, tuple) else ("?", 0)

        conn_id = self._next_conn_id
        self._next_conn_id += 1

        conn = Connection(
            id=conn_id,
            reader=reader,
            writer=writer,
            peer=PeerInfo(addr=addr, port=port),
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
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            self._connections.pop(conn_id, None)
            if self.on_disconnect:
                try:
                    await self.on_disconnect(conn)
                except Exception:
                    pass

    # ---------------- auth ----------------

    async def _authenticate(self, conn: Connection) -> None:
        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        msg = Message.from_bytes(raw)
        if not is_auth_message(msg, stage=AuthStage.INIT):
            return

        username = (msg.meta or {}).get("username", "")
        client_nonce_b64 = (msg.meta or {}).get("client_nonce", "")
        conn.username = username

        chal = self.auth_server.handle_init(username, client_nonce_b64)
        await _write_frame(conn.writer, chal.to_bytes())

        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        resp = Message.from_bytes(raw)
        if not is_auth_message(resp, stage=AuthStage.RESPONSE):
            return

        res = self.auth_server.handle_response(
            username=(resp.meta or {}).get("username", username),
            client_nonce_b64=(resp.meta or {}).get("client_nonce", ""),
            proof_b64=(resp.meta or {}).get("proof", ""),
            server_nonce_b64=(chal.meta or {}).get("server_nonce", ""),
        )
        await _write_frame(conn.writer, res.to_bytes())
        conn.is_authenticated = bool((res.meta or {}).get("ok"))
        if conn.is_authenticated:
            conn.session["auth_token"] = (res.meta or {}).get("token")

    # ---------------- key exchange ----------------

    async def _key_exchange(self, conn: Connection) -> None:
        cm = self.crypto_manager_factory()
        if cm is None:
            return

        server_pk = cm.generate_keys()

        meta1 = {
            "kx": "server_pk",
            "alg": getattr(cm, "algorithm", "Kyber512"),
            "server_pk_b64": _b64e(server_pk),
        }
        msg1 = Message(
            header=MessageHeader.new(MessageType.KEY_UPDATE, payload_len=0, meta_len=0),
            payload=b"",
            meta=meta1,
        )
        await _write_frame(conn.writer, msg1.to_bytes())

        raw = await _read_frame(conn.reader, max_len=self.max_message_size)
        msg2 = Message.from_bytes(raw)
        if msg2.header.msg_type != MessageType.KEY_UPDATE or (msg2.meta or {}).get("kx") != "client_ct":
            return

        ct_b64 = (msg2.meta or {}).get("ct_b64", "")
        ct = _b64d(ct_b64)

        cm.decapsulate(ct)
        conn.session["crypto"] = cm

        msg_ok = Message(
            header=MessageHeader.new(MessageType.KEY_UPDATE, payload_len=0, meta_len=0),
            payload=b"",
            meta={"kx": "ok"},
        )
        await _write_frame(conn.writer, msg_ok.to_bytes())


# ---------------- tiny utils ----------------

import base64 as _b64
def _b64e(b: bytes) -> str:
    return _b64.b64encode(b).decode("ascii")
def _b64d(s: str) -> bytes:
    return _b64.b64decode(s.encode("ascii"))
