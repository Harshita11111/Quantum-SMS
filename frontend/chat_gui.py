# frontend/chat_gui.py
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time
import queue

from network.client import QSMSClient
from network.message_protocol import MessageType


class ChatWindow:
    def __init__(self, username: str = None, password: str = None):
        """
        If username/password provided, attempt to connect immediately (used when
        login_gui calls the on_login callback with credentials).
        Otherwise show the small login UI and wait for user to click Connect.
        """
        self.username = None
        self.password = None
        self.client = None
        self.running = False
        self.recv_q = queue.Queue()

        # Build root window (always needed for messagebox and later chat UI)
        self.root = tk.Tk()
        self.root.title("Quantum-SMS — Login")
        self.root.geometry("400x120")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # If credentials were passed, use them and start connection immediately
        if username and password:
            self.username = username
            self.password = password
            # start connect on background thread (so UI remains responsive)
            threading.Thread(target=self._connect_and_setup, daemon=True).start()
        else:
            # Build login UI (existing behavior)
            tk.Label(self.root, text="Username").grid(row=0, column=0, padx=6, pady=6)
            self.username_entry = tk.Entry(self.root)
            self.username_entry.grid(row=0, column=1, padx=6, pady=6)

            tk.Label(self.root, text="Password").grid(row=1, column=0, padx=6, pady=6)
            self.password_entry = tk.Entry(self.root, show="*")
            self.password_entry.grid(row=1, column=1, padx=6, pady=6)

            tk.Button(self.root, text="Connect", command=self.on_connect).grid(
                row=2, column=0, columnspan=2, pady=8
            )

        # Start the tkinter mainloop (must be on main thread)
        self.root.mainloop()

    def on_connect(self):
        # called when user clicks Connect in the UI
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showinfo("Info", "Enter username and password")
            return
        # set and connect in background
        self.username = username
        self.password = password
        threading.Thread(target=self._connect_and_setup, daemon=True).start()

    def _connect_and_setup(self):
        """
        Runs in a background thread to avoid freezing the GUI.
        Connect -> authenticate -> key exchange.
        If any failure occurs, show the error on the Tkinter main thread.
        """
        try:
            client = QSMSClient(host="127.0.0.1", port=5000)
            client.connect()
            client.authenticate(self.username, self.password)
            client.key_exchange()
            self.client = client

        except Exception as e:
            err_msg = str(e)
            # show error safely on main/UI thread
            self.root.after(0, lambda m=err_msg: messagebox.showerror("Connection failed", m))
            return

        # Success — open chat window on main/UI thread
        self.root.after(0, self._open_chat_window)



    def _open_chat_window(self):
        # destroy login widgets, reuse root for chat UI
        for w in self.root.winfo_children():
            w.destroy()

        self.root.title(f"Quantum-SMS — {self.username}")
        self.root.geometry("700x480")
        self.root.resizable(False, False)

        self.chat_box = scrolledtext.ScrolledText(
            self.root, width=86, height=24, state="disabled", font=("Consolas", 11)
        )
        self.chat_box.pack(padx=10, pady=10)

        bottom = tk.Frame(self.root)
        bottom.pack(fill="x", padx=10)

        # Recipient field (optional)
        tk.Label(bottom, text="To (user_id, optional):").pack(side="left")
        self.to_entry = tk.Entry(bottom, width=12)
        self.to_entry.pack(side="left", padx=(4, 8))

        self.entry = tk.Entry(bottom, width=48, font=("Arial", 11))
        self.entry.pack(side="left", padx=(0, 8))
        self.entry.focus()

        self.send_btn = tk.Button(bottom, text="Send", width=12, command=self.send_msg)
        self.send_btn.pack(side="left")

        self.running = True
        threading.Thread(target=self.receive_loop, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.add_text("[System] Connected. Type 'quit' to exit.")

    def add_text(self, txt: str):
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", txt + "\n")
        self.chat_box.config(state="disabled")
        self.chat_box.see("end")

    def send_msg(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        to_id = self.to_entry.get().strip() or None
        try:
            # set meta "from" and optional "to"
            # QSMSClient.send_text will build Message and encrypt
            self.client.send_text(txt, from_id=self.username, to_id=to_id)
            self.add_text(f"Me: {txt}")
            self.entry.delete(0, "end")
            if txt.lower() == "quit":
                self.on_close()
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    def receive_loop(self):
        while self.running:
            try:
                msg = self.client.recv_message()
                if msg is None:
                    time.sleep(0.05)
                    continue
                # ignore auth messages
                if msg.header.msg_type == MessageType.AUTH:
                    continue
                try:
                    text = msg.payload.decode("utf-8", errors="replace").rstrip()
                except Exception:
                    text = "<binary>"
                who = msg.meta.get("from", "peer")
                # schedule UI update on main thread
                self.root.after(0, lambda txt=f"[{who}] {text}": self.add_text(txt))
            except Exception:
                break
            time.sleep(0.02)

    def on_close(self):
        self.running = False
        try:
            if self.client:
                self.client.close()
        except:
            pass
        try:
            self.root.destroy()
        except:
            pass


# Accept credentials from login_gui by supporting parameters here.
def start_chat(username: str = None, password: str = None):
    ChatWindow(username=username, password=password)


if __name__ == "__main__":
    start_chat()
