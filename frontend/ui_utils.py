# ui_utils.py
import tkinter as tk
from tkinter import messagebox

def alert(title: str, message: str):
    """Show an information popup."""
    messagebox.showinfo(title, message)

def error(title: str, message: str):
    """Show an error popup."""
    messagebox.showerror(title, message)

def center_window(window, width=350, height=300):
    """Center Tkinter window on screen."""
    screen_w = window.winfo_screenwidth()
    screen_h = window.winfo_screenheight()
    x = (screen_w // 2) - (width // 2)
    y = (screen_h // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")
