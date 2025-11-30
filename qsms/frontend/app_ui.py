# qsms/frontend/app_ui.py

from __future__ import annotations

import os
import secrets
import threading
from typing import Dict, Optional

from flask import (
    Flask,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
    flash,
    jsonify,
)

from qsms.network.client import QSMSClient
from qsms.network.message_protocol import MessageType
from qsms.database.user_management import DBUserStore

# Shared DB-backed user store
user_store = DBUserStore()

# --------------------------- config ------------------------------------

DEFAULT_QSMS_HOST = os.environ.get("QSMS_SERVER_HOST", "127.0.0.1")
DEFAULT_QSMS_PORT = int(os.environ.get("QSMS_SERVER_PORT", "5000"))

app = Flask(__name__)
app.secret_key = os.environ.get("QSMS_WEB_SECRET_KEY", "dev-secret-change-me")

_CLIENTS: Dict[str, QSMSClient] = {}
_CLIENTS_LOCK = threading.Lock()

# --------------------------- HTML templates ----------------------------

BASE_STYLES = """
<style>
  :root {
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color-scheme: dark;
  }
  body {
    margin: 0;
    padding: 0;
    background: #05060a;
    color: #f7f7ff;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .card {
    background: #111827;
    border-radius: 22px;
    padding: 26px 30px 24px;
    box-shadow: 0 18px 45px rgba(0,0,0,0.6);
    width: min(100%, 420px);
  }
  h1 { margin: 0 0 8px; font-size: 1.6rem; }
  .subtitle {
    margin-bottom: 18px;
    color: #9ca3af;
    font-size: 0.9rem;
  }
  label {
    display: block;
    margin-bottom: 4px;
    font-size: 0.8rem;
    color: #9ca3af;
  }
  input {
    width: 100%;
    padding: 8px 10px;
    border-radius: 10px;
    border: 1px solid #374151;
    background: #020617;
    color: #f9fafb;
    font-size: 0.9rem;
    box-sizing: border-box;
  }
  input:focus {
    outline: none;
    border-color: #6366f1;
    box-shadow: 0 0 0 1px rgba(99, 102, 241, 0.4);
  }
  .field { margin-bottom: 14px; }
  .btn {
    width: 100%;
    border-radius: 999px;
    padding: 9px 12px;
    border: none;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.9rem;
    background: linear-gradient(135deg, #6366f1, #ec4899);
    color: white;
  }
  .btn-small { width: auto; padding-inline: 14px; }
  .flash {
    margin-bottom: 12px;
    padding: 8px;
    border-radius: 10px;
    font-size: 0.8rem;
  }
  .flash-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: #fecaca;
  }
  .flash-success {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: #bbf7d0;
  }
  a { color: #818cf8; text-decoration: none; font-size: 0.8rem; }
  a:hover { text-decoration: underline; }
</style>
"""

FLASH_SNIPPET = """
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, msg in messages %}
      <div class="flash flash-{{ category }}">{{ msg }}</div>
    {% endfor %}
  {% endif %}
{% endwith %}
"""

# NOTICE: no "f" prefix here, and BASE_STYLES is concatenated with +
LOGIN_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>QSMS – Sign in</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLES + """
  </head>
  <body>
    <div class="card">
      <h1>Sign in</h1>
      <div class="subtitle">Sign in to your QSMS account</div>
      """ + FLASH_SNIPPET + """
      <form method="post">
        <div class="field">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" required>
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password"
                 autocomplete="current-password" required>
        </div>
        <button class="btn" type="submit">Sign in</button>
      </form>
      <div style="margin-top: 10px; font-size: 0.8rem;">
        New here? <a href="{{ url_for('register') }}">Create an account</a>
      </div>
    </div>
  </body>
</html>
"""

REGISTER_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>QSMS – Register</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLES + """
  </head>
  <body>
    <div class="card">
      <h1>Register</h1>
      <div class="subtitle">Create a QSMS account</div>
      """ + FLASH_SNIPPET + """
      <form method="post">
        <div class="field">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" required>
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password"
                 autocomplete="new-password" required>
        </div>
        <div class="field">
          <label for="password2">Confirm password</label>
          <input id="password2" name="password2" type="password"
                 autocomplete="new-password" required>
        </div>
        <button class="btn" type="submit">Create account</button>
      </form>
      <div style="margin-top: 10px; font-size: 0.8rem;">
        Already registered? <a href="{{ url_for('login') }}">Sign in</a>
      </div>
    </div>
  </body>
</html>
"""

CHAT_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>QSMS – Chat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLES + """
    <style>
      .chat-wrapper {
        display: flex;
        flex-direction: column;
        gap: 10px;
        height: 420px;
      }
      .chat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.85rem;
        color: #9ca3af;
      }
      .chat-log {
        flex: 1;
        border-radius: 12px;
        background: #020617;
        border: 1px solid #1f2937;
        padding: 10px;
        overflow-y: auto;
        font-size: 0.85rem;
      }
      .msg { margin-bottom: 8px; display: flex; }
      .msg.me { justify-content: flex-end; }
      .msg .bubble {
        max-width: 80%;
        padding: 6px 9px;
        border-radius: 12px;
      }
      .msg.me .bubble {
        background: #4f46e5;
        color: white;
        border-bottom-right-radius: 2px;
      }
      .msg.peer .bubble {
        background: #111827;
        border: 1px solid #1f2937;
        border-bottom-left-radius: 2px;
      }
      .input-row { display: flex; gap: 6px; }
      .input-row input[type="text"] { flex: 1; }
    </style>
    <script>
      async function sendMessage(ev) {
        ev.preventDefault();
        const input = document.getElementById("msg-input");
        const text = input.value.trim();
        if (!text) return;

        appendMessage("me", text);
        input.value = "";
        input.focus();

        try {
          const resp = await fetch("{{ url_for('api_send') }}", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text })
          });
          const data = await resp.json();
          if (!resp.ok || data.error) {
            appendMessage("peer", "[error] " + (data.error || "send failed"));
            return;
          }
          if (data.reply_text) {
            appendMessage("peer", data.reply_text);
          }
        } catch (err) {
          appendMessage("peer", "[network error] " + err);
        }
      }

      function appendMessage(who, text) {
        const log = document.getElementById("chat-log");
        const wrapper = document.createElement("div");
        wrapper.className = "msg " + who;
        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.textContent = text;
        wrapper.appendChild(bubble);
        log.appendChild(wrapper);
        log.scrollTop = log.scrollHeight;
      }

      window.addEventListener("load", () => {
        document.getElementById("chat-form")
                .addEventListener("submit", sendMessage);
      });
    </script>
  </head>
  <body>
    <div class="card">
      <h1>Chat</h1>
      <div class="subtitle">Post-quantum secure messaging demo</div>
      """ + FLASH_SNIPPET + """
      <div class="chat-wrapper">
        <div class="chat-header">
          <div>Logged in as <strong>{{ username }}</strong></div>
          <div><a href="{{ url_for('logout') }}">Sign out</a></div>
        </div>
        <div id="chat-log" class="chat-log"></div>
        <form id="chat-form">
          <div class="input-row">
            <input id="msg-input" type="text" placeholder="Type a message…" autocomplete="off">
            <button class="btn btn-small" type="submit">Send</button>
          </div>
        </form>
      </div>
    </div>
  </body>
</html>
"""


# --------------------------- helpers -----------------------------------


def _ensure_session_id() -> str:
    sid = session.get("sid")
    if not sid:
        sid = secrets.token_hex(16)
        session["sid"] = sid
    return sid


def _get_client(create_if_missing: bool = False) -> Optional[QSMSClient]:
    sid = _ensure_session_id()
    with _CLIENTS_LOCK:
        client = _CLIENTS.get(sid)
        if client is None and create_if_missing:
            client = QSMSClient(host=DEFAULT_QSMS_HOST, port=DEFAULT_QSMS_PORT)
            _CLIENTS[sid] = client
        return client


def _drop_client() -> None:
    sid = session.get("sid")
    if not sid:
        return
    with _CLIENTS_LOCK:
        client = _CLIENTS.pop(sid, None)
    if client is not None:
        try:
            client.close()
        except Exception:
            pass

# --------------------------- routes ------------------------------------


@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username and password are required.", "error")
        else:
            client = _get_client(create_if_missing=True)
            client.host = DEFAULT_QSMS_HOST
            client.port = DEFAULT_QSMS_PORT

            try:
                client.connect()
                client.authenticate(username, password)
                client.key_exchange()
            except Exception as e:
                _drop_client()
                flash(f"Login failed: {e}", "error")
            else:
                session["username"] = username
                flash("Successfully signed in.", "success")
                return redirect(url_for("chat"))

    return render_template_string(LOGIN_HTML)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not username or not password:
            flash("Username and password are required.", "error")
        elif password != password2:
            flash("Passwords do not match.", "error")
        else:
            try:
                user_store.add_user(username, password)
            except ValueError as e:
                flash(str(e), "error")
            except Exception as e:
                flash(f"Internal error while creating user: {e}", "error")
            else:
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))

    return render_template_string(REGISTER_HTML)


@app.route("/logout")
def logout():
    _drop_client()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/chat")
def chat():
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template_string(CHAT_HTML, username=session["username"])


@app.route("/api/send", methods=["POST"])
def api_send():
    if not session.get("username"):
        return jsonify({"error": "not authenticated"}), 401

    client = _get_client()
    if client is None or client.conn is None or client.crypto is None:
        return jsonify({"error": "not connected to QSMS server"}), 503

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "empty message"}), 400

    try:
        client.send_text(text)
        reply = client.recv_message()
    except Exception as e:
        return jsonify({"error": f"send/receive error: {e}"}), 500

    reply_text = None
    if reply is not None and reply.header.msg_type == MessageType.TEXT:
        try:
            reply_text = reply.payload.decode("utf-8", errors="replace")
        except Exception:
            reply_text = "<non-utf8 reply>"

    return jsonify({
        "ok": True,
        "reply_text": reply_text,
        "msg_type": int(reply.header.msg_type) if reply is not None else None,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
