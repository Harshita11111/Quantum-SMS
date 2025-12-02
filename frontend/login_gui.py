# frontend/login_gui.py
import tkinter as tk
from tkinter import messagebox
from typing import Callable, Optional

def start_login_window(on_login: Optional[Callable[[str, str], None]] = None):
    root = tk.Tk()
    root.title("Quantum-SMS Login")
    root.geometry("360x220")
    root.resizable(False, False)

    tk.Label(root, text="Username:", font=("Arial", 11)).pack(pady=(18, 2))
    username_entry = tk.Entry(root, font=("Arial", 11))
    username_entry.pack()

    tk.Label(root, text="Password:", font=("Arial", 11)).pack(pady=(8, 2))
    password_entry = tk.Entry(root, show="*", font=("Arial", 11))
    password_entry.pack()

    error_label = tk.Label(root, text="", fg="red", font=("Arial", 10))
    error_label.pack(pady=6)

    def open_register():
        root.destroy()
        from .register_gui import open_register_window
        open_register_window()

    def do_login(event=None):
        error_label.config(text="")
        uname = username_entry.get().strip()
        pwd = password_entry.get().strip()
        if not uname or not pwd:
            error_label.config(text="Enter username and password")
            return
        try:
            root.destroy()
            if on_login:
                on_login(uname, pwd)
        except Exception as e:
            messagebox.showerror("Login failed", str(e))

    tk.Button(root, text="Login", width=18, command=do_login).pack(pady=(6, 4))
    tk.Button(root, text="Register", width=18, command=open_register).pack()

    username_entry.focus()
    root.bind("<Return>", do_login)
    root.mainloop()
