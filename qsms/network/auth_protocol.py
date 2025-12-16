# qsms/network/auth_protocol.py
"""
QSMS Authentication Protocol (Network Layer)
(…same docstring as before…)
"""
from __future__ import annotations

import base64
import hmac
import os
import time
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, sha256
from typing import Dict, Optional, Tuple


from .message_protocol import Message, MessageHeader, MessageType

# ----------------------------- helpers ---------------------------------

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, sha256).digest()

def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

# ----------------------------- wire shapes ------------------------------

class AuthStage:
    INIT = "init"
    CHALLENGE = "challenge"
    RESPONSE = "response"
    RESULT = "result"

def build_auth_message(stage_meta: Dict) -> Message:
    header = MessageHeader.new(MessageType.AUTH, payload_len=0, meta_len=0)
    return Message(header=header, payload=b"", meta=stage_meta)

# --------------------------- user storage API ---------------------------

from dataclasses import dataclass

@dataclass
class UserRecord:
    username: str
    salt_b64: str
    pbkdf2_iter: int
    password_hash_b64: str  # PBKDF2(password, salt, iter), 32 bytes

class UserStore:
    def __init__(self) -> None:
        self._users: Dict[str, UserRecord] = {}

    def add_user(self, username: str, password: str, *, pbkdf2_iter: int = 200_000) -> None:
        salt = _rand_bytes(16)
        pw_hash = _pbkdf2(password, salt, pbkdf2_iter)
        rec = UserRecord(
            username=username,
            salt_b64=_b64e(salt),
            pbkdf2_iter=pbkdf2_iter,
            password_hash_b64=_b64e(pw_hash),
        )
        self._users[username] = rec

    def get(self, username: str) -> Optional[UserRecord]:
        return self._users.get(username)

# ----------------------------- server side ------------------------------

class AuthServer:
    def __init__(self, user_store: UserStore) -> None:
        self.user_store = user_store

    def handle_init(self, username: str, client_nonce_b64: str) -> Message:
        rec = self.user_store.get(username)
        server_nonce = _rand_bytes(16)
        salt = _rand_bytes(16) if rec is None else _b64d(rec.salt_b64)
        iterations = 200_000 if rec is None else rec.pbkdf2_iter

        meta = {
            "stage": AuthStage.CHALLENGE,
            "username": username,
            "server_nonce": _b64e(server_nonce),
            "salt": _b64e(salt),
            "pbkdf2_iter": int(iterations),
            "client_nonce": client_nonce_b64,
        }
        return build_auth_message(meta)

    def handle_response(
        self,
        username: str,
        client_nonce_b64: str,
        proof_b64: str,
        server_nonce_b64: str,
    ) -> Message:
        rec = self.user_store.get(username)
        ok = False

        if rec is not None:
            try:
                pw_key = _b64d(rec.password_hash_b64)
                server_nonce = _b64d(server_nonce_b64)
                client_nonce = _b64d(client_nonce_b64)
                expected = _hmac_sha256(pw_key, server_nonce + client_nonce)
                ok = hmac.compare_digest(expected, _b64d(proof_b64))
            except Exception:
                ok = False

        meta = {"stage": AuthStage.RESULT, "ok": bool(ok)}
        if ok:
            token_bytes = _rand_bytes(16)
            meta["token"] = _b64e(token_bytes)
            meta["server_nonce"] = server_nonce_b64
        else:
            meta["error"] = "invalid-credentials"

        return build_auth_message(meta)

# ----------------------------- client side ------------------------------

class AuthClient:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.client_nonce = _b64e(_rand_bytes(16))

    def start(self) -> Message:
        meta = {
            "stage": AuthStage.INIT,
            "username": self.username,
            "client_nonce": self.client_nonce,
            "ts": int(time.time() * 1000),
        }
        return build_auth_message(meta)

    def respond(self, challenge_msg: Message) -> Message:
        meta = challenge_msg.meta or {}
        if meta.get("stage") != AuthStage.CHALLENGE:
            raise ValueError("Unexpected stage; expected CHALLENGE")

        salt = _b64d(meta["salt"])
        iterations = int(meta["pbkdf2_iter"])
        server_nonce = _b64d(meta["server_nonce"])
        client_nonce = _b64d(meta.get("client_nonce", self.client_nonce))

        pw_key = _pbkdf2(self.password, salt, iterations)
        proof = _hmac_sha256(pw_key, server_nonce + client_nonce)

        meta_out = {
            "stage": AuthStage.RESPONSE,
            "username": self.username,
            "client_nonce": _b64e(client_nonce),
            "proof": _b64e(proof),
            "ts": int(time.time() * 1000),
        }
        return build_auth_message(meta_out)

    def parse_result(self, result_msg: Message) -> Tuple[bool, Optional[str]]:
        meta = result_msg.meta or {}
        if meta.get("stage") != AuthStage.RESULT:
            raise ValueError("Unexpected stage; expected RESULT")
        return bool(meta.get("ok")), meta.get("token")

# ----------------------------- utils -----------------------------------

def is_auth_message(msg: Message, *, stage: Optional[str] = None) -> bool:
    if msg.header.msg_type != MessageType.AUTH:
        return False
    if stage is None:
        return True
    return (msg.meta or {}).get("stage") == stage

# ---------------------------- self-test --------------------------------

if __name__ == "__main__":
    print("[+] QSMS auth_protocol self-test")
    store = UserStore()
    store.add_user("alice", "correct horse battery staple")
    server = AuthServer(store)
    client = AuthClient("alice", "correct horse battery staple")
    init = client.start()
    chal = server.handle_init(init.meta["username"], init.meta["client_nonce"])
    resp = client.respond(chal)
    res = server.handle_response(
        username=resp.meta["username"],
        client_nonce_b64=resp.meta["client_nonce"],
        proof_b64=resp.meta["proof"],
        server_nonce_b64=chal.meta["server_nonce"],
    )
    ok, token = client.parse_result(res)
    print("Auth OK:", ok, "token:", token is not None)
