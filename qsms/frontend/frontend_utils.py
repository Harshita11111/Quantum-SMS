# frontend_utils.py
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Dict, Any

# --- QSMS primitives (from your repo) ---
from qsms.network.client import QSMSClient  # blocking TCP client with auth & KEM KX
from qsms.network.message_protocol import Message, MessageHeader, MessageType  # wire msg
# ^ client.send_text() and Message.[to/from]_bytes() are used under the hood.
#   Auth and KEM flow are handled by QSMSClient.authenticate()/key_exchange()
#   and CryptoManager inside it.  (See repo modules.)  [auth/crypto/protocol]
#   refs: auth_protocol.py, message_protocol.py, crypto_manager.py


# =========================
# Public data structures
# =========================

@dataclass
class User:
    username: str


@dataclass
class ChatMessage:
    """
    UI-friendly representation of a QSMS message.
    Only TEXT is modelled here; extend as needed.
    """
    sender: str
    recipient: str
    text: str
    ts: datetime = field(default_factory=datetime.utcnow)
    raw: Optional[Message] = None  # keep the parsed message if caller needs it


# =========================
# Frontend session façade
# =========================

class FrontendSession:
    """
    Wraps the blocking QSMSClient in a UI-friendly shell.

    - connect() / login() / start() set up the TCP connection,
      perform authentication and the Kyber KEM handshake (AES keys & AAD).
    - send_text() sends a chat message.
    - subscribe(cb) registers a callback invoked for each inbound Message.
      Returns an unsubscribe function.
    - close() tears everything down cleanly.

    Threading model:
      A dedicated receiver thread blocks on _client.recv_message()
      and dispatches each message to all subscribers.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        self.host = host
        self.port = port

        self._client = QSMSClient(host=host, port=port)
        self._user: Optional[User] = None

        self._recv_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._subs_lock = threading.Lock()
        self._subscribers: List[Callable[[Message], None]] = []

    # ---------- lifecycle ----------

    def connect(self) -> None:
        """Open TCP connection to the server."""
        self._client.connect()

    def login(self, username: str, password: str) -> None:
        """
        Run the auth handshake + KEM key exchange.
        On success, self.user is set.
        """
        self._client.authenticate(username, password)  # AUTH flow (INIT/CHAL/RESP/RESULT)
        self._client.key_exchange()                    # Kyber encapsulate/decapsulate -> AES keys
        self._user = User(username=username)

    def start_receiving(self) -> None:
        """
        Start the background receive loop (idempotent).
        Call after login().
        """
        if self._recv_thread and self._recv_thread.is_alive():
            return
        self._stop_flag.clear()
        t = threading.Thread(target=self._recv_loop, name="qsms-recv", daemon=True)
        t.start()
        self._recv_thread = t

    @property
    def user(self) -> Optional[User]:
        return self._user

    # ---------- messaging ----------

    def send_text(self, text: str) -> None:
        """
        Send a TEXT message with UTF-8 payload.
        (Uses QSMSClient.send_text() which wraps MessageHeader.new + AES-GCM.) 
        """
        self._client.send_text(text)

    def subscribe(self, callback: Callable[[Message], None]) -> Callable[[], None]:
        """
        Register a callback invoked with each inbound QSMS Message.
        Returns an unsubscribe() function.
        """
        with self._subs_lock:
            self._subscribers.append(callback)

        def _unsubscribe() -> None:
            with self._subs_lock:
                try:
                    self._subscribers.remove(callback)
                except ValueError:
                    pass

        return _unsubscribe

    # ---------- helpers ----------

    def _dispatch(self, msg: Message) -> None:
        with self._subs_lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(msg)
            except Exception:
                # Keep UI stable even if a handler fails
                pass

    def _recv_loop(self) -> None:
        """
        Blocks waiting for encrypted frames, parses into Message,
        and dispatches to subscribers. Exits when stop_flag is set
        or when socket closes/errors out.
        """
        while not self._stop_flag.is_set():
            try:
                m = self._client.recv_message()
            except Exception:
                break
            if m is None:
                break
            self._dispatch(m)

        # loop exit -> close socket if still open
        try:
            self._client.close()
        except Exception:
            pass

    def close(self) -> None:
        """Stop background thread and close network resources."""
        self._stop_flag.set()
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=1.5)
        try:
            self._client.close()
        finally:
            self._recv_thread = None

    # ---------- convenience for UI adapters ----------

    @staticmethod
    def to_chat_message(msg: Message, *, self_username: Optional[str] = None) -> Optional[ChatMessage]:
        """
        Map a QSMS TEXT message to ChatMessage for UI.
        Non-TEXT messages return None (extend if you need more types).
        """
        if msg.header.msg_type != MessageType.TEXT:
            return None

        # Try to extract sender/recipient from meta if present
        meta = msg.meta or {}
        sender = str(meta.get("from") or meta.get("sender") or (self_username or "peer"))
        recp   = str(meta.get("to")   or meta.get("recipient") or (self_username or "me"))
        try:
            text = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            text = "<non-utf8>"

        # If the header timestamp is in ms, use it; otherwise now()
        ts_ms = getattr(msg.header, "timestamp_ms", None)
        ts = datetime.utcfromtimestamp(ts_ms / 1000.0) if isinstance(ts_ms, int) else datetime.utcnow()

        return ChatMessage(sender=sender, recipient=recp, text=text, ts=ts, raw=msg)


# =========================
# Tiny utility helpers
# =========================

def validate_username(name: str) -> bool:
    """Basic username check for UI forms."""
    name = (name or "").strip()
    return 1 <= len(name) <= 32 and all(c.isalnum() or c in ("_", "-", ".") for c in name)


def format_time(ts: datetime) -> str:
    """Nice compact timestamp for chat bubbles."""
    return ts.strftime("%H:%M")


# =========================
# Quick manual demo
# =========================

if __name__ == "__main__":
    """
    Quick manual smoke-test:

   
    """
    import sys

    host = "127.0.0.1"
    port = 5000
    username = "alice"
    password = "correct horse battery staple"

    sess = FrontendSession(host=host, port=port)
    try:
        print("[frontend] connecting…")
        sess.connect()
        print("[frontend] logging in…")
        sess.login(username, password)
        sess.start_receiving()

        # subscribe to print all inbound messages as chat lines
        sess.subscribe(lambda m: print(f"< {FrontendSession.to_chat_message(m, self_username=username)}"))

        print("[frontend] type to send, Ctrl+C to exit.")
        while True:
            line = input("> ")
            if line.strip().lower() == "quit":
                break
            sess.send_text(line)

    except KeyboardInterrupt:
        pass
    finally:
        sess.close()
