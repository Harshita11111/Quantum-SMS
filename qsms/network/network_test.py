# qsms/network/network_test.py
"""
Pytest integration tests for the QSMS networking stack.

Run:
    pytest -q qsms/network/network_test.py
"""

from __future__ import annotations

# --- Make the test robust to being run from the wrong working dir -----------
try:
    from qsms.network.server import QSMSServer  # type: ignore
    from qsms.network.client import QSMSClient  # type: ignore
    from qsms.network.message_protocol import (  # type: ignore
        Message, MessageHeader, MessageType
    )
except ModuleNotFoundError:
    # Add project root (the folder that contains 'qsms/') to sys.path
    import sys
    from pathlib import Path
    ROOT = Path(__file__).resolve().parents[2]  # .../Quantum-SMS
    sys.path.insert(0, str(ROOT))
    # Retry imports
    from qsms.network.server import QSMSServer
    from qsms.network.client import QSMSClient
    from qsms.network.message_protocol import Message, MessageHeader, MessageType

import socket
import threading
import time
import random
import string
from typing import Optional, Tuple, List

import pytest


# --------------------------- helpers ---------------------------

def _find_free_port() -> int:
    """Return an available localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _rand_text(n: int) -> str:
    alphabet = string.ascii_letters + string.digits + " _-.,!?/\\:;@#"
    return "".join(random.choice(alphabet) for _ in range(n))


def _new_client(host: str, port: int) -> QSMSClient:
    """Create → connect → authenticate → key exchange → return ready client."""
    c = QSMSClient(host=host, port=port)
    c.connect()
    # Must match the user added by the server fixture
    c.authenticate("alice", "correct horse battery staple")
    c.key_exchange()
    return c


# --------------------------- server fixture ---------------------------

class _ServerThread(threading.Thread):
    """Run QSMSServer in its own asyncio loop in a background thread."""
    def __init__(self, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._loop = None
        self._srv: Optional[QSMSServer] = None
        self._ready = threading.Event()
        self._err: Optional[BaseException] = None

    def run(self) -> None:
        import asyncio

        async def _main():
            try:
                self._srv = QSMSServer(self.host, self.port)
                # Add demo user used by tests
                self._srv.add_user("alice", "correct horse battery staple")
                await self._srv.start()
                self._ready.set()
                await self._srv.serve_forever()
            except asyncio.CancelledError:
                pass
            except BaseException as e:
                self._err = e
            finally:
                if self._srv is not None:
                    try:
                        await self._srv.close()
                    except Exception:
                        pass

        try:
            import asyncio
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(_main())
        finally:
            if self._loop is not None:
                try:
                    self._loop.close()
                except Exception:
                    pass

    def wait_ready(self, timeout: float = 5.0) -> None:
        if not self._ready.wait(timeout):
            raise TimeoutError("Server did not start in time")
        if self._err:
            raise self._err

    def stop(self) -> None:
        """Request graceful shutdown."""
        if not self._loop or not self._srv:
            return
        import asyncio
        fut = asyncio.run_coroutine_threadsafe(self._srv.close(), self._loop)
        try:
            fut.result(timeout=3.0)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)


@pytest.fixture(scope="session")
def server_addr() -> Tuple[str, int]:
    """
    Session-scoped server. Spins up once, yields (host, port), then shuts down.
    """
    host = "127.0.0.1"
    port = _find_free_port()
    thr = _ServerThread(host, port)
    thr.start()
    thr.wait_ready()
    yield host, port
    try:
        thr.stop()
    finally:
        thr.join(timeout=3.0)


# --------------------------- tests ---------------------------

def test_message_protocol_roundtrip():
    """Serialize/deserialize a TEXT message and verify round-trip integrity."""
    payload = b"hello-msg-proto"
    msg_out = Message(
        header=MessageHeader.new(MessageType.TEXT, payload_len=len(payload), meta_len=0),
        payload=payload,
        meta={"ts": 1234567890},
    )
    wire = msg_out.to_bytes()
    msg_in = Message.from_bytes(wire)
    assert msg_in.header.msg_type == MessageType.TEXT
    assert msg_in.payload == payload


def test_auth_and_echo(server_addr):
    host, port = server_addr
    c = _new_client(host, port)
    try:
        msg = "hello from pytest"
        c.send_text(msg)
        r = c.recv_message()
        assert r is not None, "no reply from server"
        assert r.header.msg_type == MessageType.TEXT
        assert r.payload.decode("utf-8").rstrip() == msg
        assert c.crypto is not None  # crypto must be active post-KX
    finally:
        c.close()


def test_large_payload(server_addr):
    host, port = server_addr
    c = _new_client(host, port)
    try:
        big = _rand_text(256 * 1024)  # 256 KB through AES-GCM + framing
        c.send_text(big)
        r = c.recv_message()
        assert r is not None, "no reply for large payload"
        assert r.header.msg_type == MessageType.TEXT
        assert r.payload.decode("utf-8") == big
    finally:
        c.close()


def test_multi_clients_concurrent(server_addr):
    host, port = server_addr
    N = 5
    msgs = [_rand_text(64) for _ in range(N)]
    results: List[bool] = []

    def worker(txt: str):
        ok = False
        c = None
        try:
            c = _new_client(host, port)
            c.send_text(txt)
            r = c.recv_message()
            ok = (r is not None and
                  r.header.msg_type == MessageType.TEXT and
                  r.payload.decode("utf-8") == txt)
        finally:
            if c:
                c.close()
            results.append(ok)

    threads = [threading.Thread(target=worker, args=(m,)) for m in msgs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert len(results) == N
    assert all(results), f"some clients failed: {results}"


def test_latency_basic(server_addr):
    host, port = server_addr
    c = _new_client(host, port)
    try:
        trials = 5
        t0 = time.perf_counter()
        for _ in range(trials):
            c.send_text("ping")
            r = c.recv_message()
            assert r is not None
        dt = (time.perf_counter() - t0) / trials
        # Generous threshold to avoid CI flakiness.
        assert dt < 1.0, f"unexpectedly high avg RTT: {dt:.3f}s"
    finally:
        c.close()
