# run.py
"""
Quantum-SMS Launcher
- Initializes DB
- Starts QSMS server in background thread
- Launches frontend GUI (Tkinter) on main thread
"""

from __future__ import annotations
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "Backend"))
sys.path.insert(0, str(ROOT / "network"))
sys.path.insert(0, str(ROOT / "frontend"))

def init_database():
    try:
        print("[DATABASE] Initializing SQLAlchemy + MySQL...")
        from Backend.database import Base, engine
        Base.metadata.create_all(bind=engine)
        print("[DATABASE] OK")
    except Exception as e:
        print("[DATABASE ERROR]", e)
        traceback.print_exc()

def start_qsms_server(host="127.0.0.1", port=5000):
    import asyncio
    from network.server import QSMSServer

    async def _server_main():
        try:
            server = QSMSServer(host, port)
            await server.start()
            print(f"[SERVER] Running on {host}:{port}")
            await server.serve_forever()
        except Exception as e:
            print("[SERVER ERROR]", e)
            traceback.print_exc()

    def server_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_server_main())

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    time.sleep(0.6)

def start_frontend():
    print("[FRONTEND] Launching Login GUI...")
    try:
        from frontend.login_gui import start_login_window
        from frontend.chat_gui import start_chat
        start_login_window(on_login=start_chat)
    except Exception as e:
        print("[FRONTEND ERROR]", e)
        traceback.print_exc()

def main():
    print("====================================")
    print(" Quantum-SMS Secure Chat Launcher")
    print("====================================")
    init_database()
    print("[SERVER] Starting QSMS Server...")
    start_qsms_server()
    start_frontend()

if __name__ == "__main__":
    main()
