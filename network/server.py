# network/server.py
"""
QSMS TCP server (final working version).
Uses database-backed authentication (network.auth_protocol.AuthServer).
"""

from __future__ import annotations
import asyncio
from typing import Optional
from .connection_handler import ConnectionHandler, send_message
from .auth_protocol import AuthServer
from .message_protocol import Message, MessageType

class QSMSServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        self.host = host
        self.port = port
        self._handler: Optional[ConnectionHandler] = None

    async def start(self) -> None:
        try:
            if self._handler is not None:
                return

            auth = AuthServer()

            async def _log_and_echo(conn, msg: Message):
                if msg.header.msg_type == MessageType.TEXT:
                    try:
                        text = msg.payload.decode("utf-8", errors="replace").rstrip()
                    except Exception:
                        text = "<binary>"
                    who = conn.username or f"conn#{conn.id}"
                    print(f"[srv] {who}: {text}")
                    await send_message(conn, msg)

            self._handler = ConnectionHandler(
                auth_server=auth,
                on_message=_log_and_echo,
            )

            await self._handler.start(self.host, self.port)
            print(f"[+] QSMS server is listening on {self.host}:{self.port}")

        except Exception as e:
            print("[SERVER START ERROR]", e)
            import traceback
            traceback.print_exc()
            raise

    async def serve_forever(self) -> None:
        if not self._handler:
            await self.start()
        await self._handler.serve_forever()

    async def close(self) -> None:
        if self._handler:
            await self._handler.shutdown()
            print("[+] QSMS server shut down.")
            self._handler = None

    def run(self) -> None:
        async def _runner():
            await self.start()
            await self.serve_forever()

        try:
            asyncio.run(_runner())
        except KeyboardInterrupt:
            print("[SERVER] KeyboardInterrupt — shutting down")
            try:
                asyncio.run(self.close())
            except RuntimeError:
                pass

if __name__ == "__main__":
    QSMSServer().run()
