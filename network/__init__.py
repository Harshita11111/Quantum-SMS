# """
# qsms.network

# Server–client networking, authentication handshake, message protocol, and
# connection orchestration for the Quantum-Safe Messaging (QSMS) project.

# This package re-exports the core public API so you can write:
#     from qsms.network import QSMSServer, QSMSClient, Message, MessageType, ...

# Files:
#     server.py              -> QSMSServer (asyncio server)                   # re-exported
#     client.py              -> QSMSClient (auth + KEM + encrypted I/O)       # re-exported
#     connection_handler.py  -> ConnectionHandler, send_message               # re-exported
#     message_protocol.py    -> Message, MessageHeader, MessageType, helpers  # re-exported
#     auth_protocol.py       -> AuthServer, AuthClient, UserStore, AuthStage  # re-exported
# """

# from __future__ import annotations

# # Server
# from .server import QSMSServer

# # Client
# from .client import QSMSClient

# # Connection orchestration & encrypted send helper
# from .connection_handler import ConnectionHandler, send_message

# # Message protocol (binary header + meta + payload)
# from .message_protocol import (
#     Message,
#     MessageHeader,
#     MessageType,
#     build_ping,
#     build_pong,
# )

# # Authentication protocol (pre–key-exchange login)
# from .auth_protocol import (
#     AuthServer,
#     AuthClient,
#     UserStore,
#     AuthStage,
#     is_auth_message,
# )

# __all__ = [
#     # Server / client
#     "QSMSServer",
#     "QSMSClient",

#     # Connection layer
#     "ConnectionHandler",
#     "send_message",

#     # Message protocol
#     "Message",
#     "MessageHeader",
#     "MessageType",
#     "build_ping",
#     "build_pong",

#     # Auth protocol
#     "AuthServer",
#     "AuthClient",
#     "UserStore",
#     "AuthStage",
#     "is_auth_message",
# ]

# # Simple package version tag (bump as needed)
# __version__ = "0.1.0"
# network/__init__.py

from .server import QSMSServer
from .client import QSMSClient
from .message_protocol import Message, MessageHeader, MessageType
from .auth_protocol import AuthServer, AuthStage, is_auth_message
from .connection_handler import ConnectionHandler, send_message
