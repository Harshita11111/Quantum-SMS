# frontend/register_gui.py
import tkinter as tk
from tkinter import messagebox
from Backend.auth_service import register_user

def open_register_window():
    root = tk.Tk()
    root.title("QSMS Registration")
    root.geometry("380x320")
    root.resizable(False, False)

    tk.Label(root, text="Create New Account", font=("Arial", 12, "bold")).pack(pady=12)

    tk.Label(root, text="Username").pack()
    username_entry = tk.Entry(root, width=32)
    username_entry.pack()

    tk.Label(root, text="Email").pack(pady=(8,0))
    email_entry = tk.Entry(root, width=32)
    email_entry.pack()

    tk.Label(root, text="Password").pack(pady=(8,0))
    password_entry = tk.Entry(root, show="*", width=32)
    password_entry.pack()

    error_label = tk.Label(root, text="", fg="red")
    error_label.pack(pady=6)

    def perform_register(event=None):
        error_label.config(text="")
        username = username_entry.get().strip()
        email = email_entry.get().strip()
        password = password_entry.get().strip()

        if not username or not password or not email:
            error_label.config(text="All fields are required.")
            return

        ok, msg = register_user(username, email, password)
        if ok:
            messagebox.showinfo("Success", "Registered — please login")
            root.destroy()
            from .login_gui import start_login_window
            start_login_window(on_login=None)
        else:
            error_label.config(text=str(msg))

    tk.Button(root, text="Register", width=20, command=perform_register).pack(pady=10)
    tk.Button(root, text="Back to Login", width=20, command=lambda: (root.destroy(), __import__("frontend.login_gui").login_gui.start_login_window())).pack()

    username_entry.focus()
    root.bind("<Return>", perform_register)
    root.mainloop()
