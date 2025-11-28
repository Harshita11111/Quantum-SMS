# network/auth_protocol.py
"""
Database-backed Authentication for QSMS.
Uses Backend.auth_service.login_user() to validate credentials.
"""

from __future__ import annotations
from dataclasses import dataclass
import base64
import os

from Backend.auth_service import login_user
from .message_protocol import Message, MessageHeader, MessageType


# ---------------------- Stages ----------------------
class AuthStage:
    INIT = "init"
    CHALLENGE = "challenge"
    RESPONSE = "response"
    RESULT = "result"


def is_auth_message(msg: Message, stage: str) -> bool:
    return (
        msg.header.msg_type == MessageType.AUTH
        and (msg.meta or {}).get("stage") == stage
    )


# ---------------------- SERVER SIDE ----------------------
class AuthServer:
    """
    Steps:
      1. INIT (client gives username + client_nonce)
      2. CHALLENGE (server returns server_nonce)
      3. RESPONSE (client replies with password)
      4. RESULT (ok / fail)
    """

    def __init__(self):
        pass

    def handle_init(self, username: str, client_nonce_b64: str) -> Message:
        server_nonce = base64.b64encode(os.urandom(16)).decode()

        header = MessageHeader.new(
            MessageType.AUTH,
            payload_len=0,
            meta_len=0,
        )

        return Message(
            header=header,
            payload=b"",
            meta={
                "stage": AuthStage.CHALLENGE,
                "username": username,
                "client_nonce": client_nonce_b64,
                "server_nonce": server_nonce,
            },
        )

    def handle_response(
        self,
        username: str,
        password: str,
        client_nonce_b64: str,
        server_nonce_b64: str,
    ) -> Message:

        ok, result = login_user(username, password)

        if ok:
            header = MessageHeader.new(
                MessageType.AUTH,
                payload_len=0,
                meta_len=0,
            )
            return Message(
                header=header,
                payload=b"",
                meta={
                    "stage": AuthStage.RESULT,
                    "ok": True,
                    "user_id": result,
                },
            )

        header = MessageHeader.new(
            MessageType.AUTH,
            payload_len=0,
            meta_len=0,
        )
        return Message(
            header=header,
            payload=b"",
            meta={
                "stage": AuthStage.RESULT,
                "ok": False,
                "reason": result,
            },
        )


# ---------------------- CLIENT SIDE ----------------------
@dataclass
class AuthClient:
    username: str
    password: str
    client_nonce: bytes = os.urandom(16)

    def start(self) -> Message:
        header = MessageHeader.new(
            MessageType.AUTH,
            payload_len=0,
            meta_len=0,
        )
        return Message(
            header=header,
            payload=b"",
            meta={
                "stage": AuthStage.INIT,
                "username": self.username,
                "client_nonce": base64.b64encode(self.client_nonce).decode(),
            },
        )

    def respond(self, msg: Message) -> Message:
        header = MessageHeader.new(
            MessageType.AUTH,
            payload_len=0,
            meta_len=0,
        )
        return Message(
            header=header,
            payload=b"",
            meta={
                "stage": AuthStage.RESPONSE,
                "username": self.username,
                "client_nonce": msg.meta["client_nonce"],
                "server_nonce": msg.meta["server_nonce"],
                "password": self.password,
            },
        )

    def parse_result(self, msg: Message):
        return msg.meta.get("ok"), msg.meta.get("user_id")
