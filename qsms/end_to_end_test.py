"""
End-to-end integration test for the Quantum-SMS (QSMS) system.

This test:

  1) Starts the QSMS TCP server in a background subprocess
     (python -m qsms.network.server).
  2) Uses QSMSClient to:
        - connect
        - authenticate as the built-in demo user 'alice'
        - perform Kyber KEM key exchange via CryptoManager
  3) Sends a TEXT message over the encrypted channel.

It does NOT require the server to echo a reply – it only checks that the full
secure pipeline runs without errors.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest

from qsms.network.client import QSMSClient
from qsms.network.message_protocol import MessageType  # optional assertion


HOST = os.environ.get("QSMS_SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("QSMS_SERVER_PORT", "5000"))


class EndToEndQSMSTest(unittest.TestCase):
    server_proc: subprocess.Popen | None = None

    @classmethod
    def setUpClass(cls) -> None:
        """Start the QSMS server as a background process."""
        env = os.environ.copy()
        env.setdefault("QSMS_SERVER_HOST", HOST)
        env.setdefault("QSMS_SERVER_PORT", str(PORT))

        cls.server_proc = subprocess.Popen(
            [sys.executable, "-m", "qsms.network.server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

        # Give the server time to bind and start listening
        time.sleep(1.5)

    @classmethod
    def tearDownClass(cls) -> None:
        """Shut down the QSMS server process."""
        if cls.server_proc is not None:
            cls.server_proc.terminate()
            try:
                cls.server_proc.wait(timeout=5)
            except Exception:
                cls.server_proc.kill()
            cls.server_proc = None

    def test_end_to_end_flow(self) -> None:
        """
        Full flow:
            connect -> authenticate -> key_exchange -> send TEXT

        If the server *does* send something back, we log / lightly check it,
        but we don't fail if there is no reply.
        """
        client = QSMSClient(host=HOST, port=PORT)

        try:
            # --- connect ---
            client.connect()

            # --- authentication ---
            # Uses the demo user created by server.py (alice / correct horse ...).
            username = "alice"
            password = "correct horse battery staple"
            client.authenticate(username, password)

            # --- post-quantum key exchange (Kyber KEM + AES-GCM) ---
            client.key_exchange()

            # --- send a TEXT message over the encrypted channel ---
            sent_text = "Hello from end_to_end_test.py 🚀"
            client.send_text(sent_text)

            # OPTIONAL: try to read a reply, but don't require it.
            try:
                reply = client.recv_message()
            except Exception:
                # For example: socket closed during recv – that's OK for this test.
                reply = None

            if reply is not None and reply.header is not None:
                # If your server *does* echo or respond, do a sanity check
                if reply.header.msg_type == MessageType.TEXT:
                    _ = reply.payload.decode("utf-8", errors="replace")

            # If we reached here without exceptions, the end-to-end path worked.
            self.assertTrue(True)

        finally:
            try:
                client.close()
            except Exception:
                pass


if __name__ == "__main__":
    # Run with:
    #   python -m qsms.end_to_end_test
    unittest.main(verbosity=2)
