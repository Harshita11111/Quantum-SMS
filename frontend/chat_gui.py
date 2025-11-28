# frontend/chat_gui.py
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time

from network.client import QSMSClient

class ChatWindow:
    def __init__(self, username: str, password: str, host="127.0.0.1", port=5000):
        self.username = username
        self.password = password
        self.client = None
        self.running = False

        try:
            self.client = QSMSClient(host, port)
            self.client.connect()
            self.client.authenticate(username, password)
            self.client.key_exchange()
        except Exception as e:
            messagebox.showerror("Connection failed", f"{e}")
            if self.client:
                try:
                    self.client.close()
                except:
                    pass
            return

        self.root = tk.Tk()
        self.root.title(f"Quantum-SMS — {username}")
        self.root.geometry("700x480")
        self.root.resizable(False, False)

        self.chat_box = scrolledtext.ScrolledText(self.root, width=86, height=24, state="disabled", font=("Consolas", 11))
        self.chat_box.pack(padx=10, pady=10)

        bottom = tk.Frame(self.root)
        bottom.pack(fill="x", padx=10)

        self.entry = tk.Entry(bottom, width=60, font=("Arial", 11))
        self.entry.pack(side="left", padx=(0,8))
        self.entry.focus()

        tk.Button(bottom, text="Send", width=12, command=self.send_msg).pack(side="left")

        self.running = True
        threading.Thread(target=self.receive_loop, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.entry.bind("<Return>", lambda e: self.send_msg())
        self.add_text("[System] Connected. Type 'quit' to exit.")
        self.root.mainloop()

    def add_text(self, txt: str):
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", txt + "\n")
        self.chat_box.config(state="disabled")
        self.chat_box.see("end")

    def send_msg(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        try:
            self.client.send_text(txt)
            self.add_text(f"Me: {txt}")
            self.entry.delete(0, 'end')
            if txt.lower() == "quit":
                self.on_close()
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    def receive_loop(self):
        while self.running:
            try:
                msg = self.client.recv_message()
                if msg is None:
                    time.sleep(0.1)
                    continue
                if msg.header.msg_type == 1:  # AUTH or other metadata
                    continue
                text = msg.payload.decode("utf-8", errors="replace").rstrip()
                self.add_text(f"Peer: {text}")
            except Exception:
                break
            time.sleep(0.05)

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

def start_chat(username: str, password: str):
    ChatWindow(username, password)
