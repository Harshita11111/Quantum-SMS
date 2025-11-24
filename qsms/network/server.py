# qsms/network/server.py
"""
QSMS TCP server built on top of the asyncio ConnectionHandler.
Logs inbound messages and echoes them back after:
  1) Authentication (auth_protocol)
  2) Kyber-based key exchange (crypto_manager via connection_handler)
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .connection_handler import ConnectionHandler, send_message
from .auth_protocol import AuthServer, UserStore
from .message_protocol import Message, MessageType


class QSMSServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.host = host
        self.port = port
        self.user_store = UserStore()
        self._handler: Optional[ConnectionHandler] = None

    # --- user management (demo) ---
    def add_user(self, username: str, password: str, *, iterations: int = 200_000) -> None:
        self.user_store.add_user(username, password, pbkdf2_iter=iterations)

    # --- server lifecycle ---
    async def start(self) -> None:
        if self._handler is not None:
            return

        auth = AuthServer(self.user_store)

        async def _log_and_echo(conn, msg: Message):
            # Log inbound TEXT messages on the server console, then echo them back
            if msg.header.msg_type == MessageType.TEXT:
                try:
                    text = msg.payload.decode("utf-8", errors="replace").rstrip()
                except Exception:
                    text = f"<{len(msg.payload)} bytes>"
                who = conn.username or f"conn#{conn.id}"
                print(f"[srv] {who}: {text}")
                await send_message(conn, msg)
            else:
                # For non-TEXT messages, do nothing (or add your routing here)
                pass

        self._handler = ConnectionHandler(
            auth_server=auth,
            on_message=_log_and_echo,   # <-- this is the key change
        )
        await self._handler.start(self.host, self.port)
        print(f"[+] QSMS server listening on {self.host}:{self.port}")

    async def serve_forever(self) -> None:
        if self._handler is None:
            await self.start()
        assert self._handler is not None
        await self._handler.serve_forever()

    async def close(self) -> None:
        if self._handler is not None:
            await self._handler.shutdown()
            self._handler = None
        print("[+] QSMS server shut down.")

    # --- sync runner convenience ---
    def run(self) -> None:
        async def _runner():
            await self.start()
            try:
                await self.serve_forever()
            finally:
                await self.close()

        try:
            asyncio.run(_runner())
        except KeyboardInterrupt:
            try:
                asyncio.run(self.close())
            except RuntimeError:
                pass


if __name__ == "__main__":
    """
    Run from project root (folder containing `qsms/`):

        python -m qsms.network.server
    """
    server = QSMSServer(host="127.0.0.1", port=5000)
    # Credentials must match the client
    server.add_user("alice", "correct horse battery staple")
    server.run()
