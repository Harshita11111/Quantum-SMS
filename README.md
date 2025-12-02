<h1 align="center">🔒 Quantum-SMS (Tahalka Code)</h1>
<h3 align="center">Post-Quantum Encrypted Messaging • AES-256-GCM • Kyber KEM • Tkinter GUI • Async Server</h3>

<p align="center">
  <b>Secure messaging built for the post-quantum era.</b><br>
  End-to-end encrypted · PQC handshake · Real-time chat · Cross-platform
</p>

<p align="center">

<a><img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python"></a>
<a><img src="https://img.shields.io/badge/Database-MySQL-orange?logo=mysql"></a>
<a><img src="https://img.shields.io/badge/Encryption-AES--GCM-green"></a>
<a><img src="https://img.shields.io/badge/PQC-Kyber512-purple"></a>
<a><img src="https://img.shields.io/badge/OS-Windows%20Supported-success"></a>
<a><img src="https://img.shields.io/badge/License-MIT-lightgrey"></a>

</p>

                     ┌──────────────────────────┐
                     │        Tkinter UI        │
                     │  (Login / Register /Chat)│
                     └──────────────┬───────────┘
                                    │
                                    ▼
                       ┌────────────────────┐
                       │    QSMS Client     │
                       │(connect/auth/kex)  │
                       └──────────┬─────────┘
                                  │Encrypted Socket
                                  ▼
                   ┌─────────────────────────────────┐
                   │          QSMS Server            │
                   │  Asyncio · Auth · KEX · Router  │
                   └───────────┬───────────┬────────┘
                               │           │
                          Auth Service   Message Router
                               │           │
                               ▼           ▼
                        ┌────────────────────────┐
                        │        MySQL DB        │
                        │  users · hashes · meta │
                        └────────────────────────┘


                         ┌──────────────────────────────┐
                         │        Client Startup         │
                         └──────────────┬───────────────┘
                                        │
                                        ▼
                          Connect to QSMS Server (127.0.0.1:5000)
                                        │
                                        ▼
                         ┌────────────────────────────────────────┐
                         │      1. Authentication (Username/Pass) │
                         └────────────────────────────────────────┘
                                        │
                                        │  Login UI → sends {username, password}
                                        ▼
                             Server validates credentials
                                        │
                          ┌─────────────┴──────────────┐
                          │ Auth Success                │
                          │ Auth Failed → Error popup   │
                          └─────────────┬──────────────┘
                                        │
                                        ▼
                     ┌───────────────────────────────────────────┐
                     │     2. Post-Quantum Key Exchange (KEM)     │
                     └───────────────────────────────────────────┘
                                        │
            ┌──────────────────────────────────────────────────────────────────┐
            │  Server → sends Kyber (or MockKEM) Public Key (pk)              │
            │  Client → Encapsulate(pk) → ciphertext(ct), shared_secret(ss)   │
            │  Server → Decapsulate(ct) → shared_secret(ss₂)                  │
            │  Both sides: derive AES-256-GCM key from shared_secret          │
            └──────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │     3. Secure Messaging (AES-256-GCM)         │
                    └──────────────────────────────────────────────┘
                                        │
                ┌─────────────────────────────────────────────────────────┐
                │ Client encrypts: AES-GCM(plaintext → ciphertext + tag) │
                │ Server decrypts: AES-GCM(nonce, ciphertext, tag)       │
                │ All chat messages → fully encrypted end-to-end         │
                └─────────────────────────────────────────────────────────┘
                                        │
                                        ▼
  ┌───────────────────┐       ┌───────────────────┐       ┌─────────────────────┐
  │    Login Window    │─────▶│   Chat Window UI  │─────▶│  Encrypted Messages │
  └───────────────────┘       └───────────────────┘       └─────────────────────┘
                 ▲                        │
                 │                        ▼
        (Optional Register)        QSMS Python Server


┌────────────┐
│  Login UI  │
└─────┬──────┘
      │ username+password
      ▼
┌────────────┐
│  Auth API  │
└─────┬──────┘
      │ success
      ▼
┌──────────────────────┐
│ PQ Key Exchange (KEM)│
└─────┬────────────────┘
      │ AES key derived
      ▼
┌───────────────┐
│ Chat Window UI│
└─────┬─────────┘
      │ encrypted messages
      ▼
┌───────────────┐
│ QSMS Server   │
└───────────────┘


Login Window
     │
     ▼
Register (optional)
     │
     ▼
Chat Window
     │
     ▼
Encrypted Messages


## 🧩 Technology Stack

| Layer | Technology |
|------|------------|
| **Frontend (GUI)** | Tkinter |
| **Backend API** | Python + AsyncIO |
| **Database** | MySQL + SQLAlchemy ORM |
| **Encryption** | AES-256-GCM |
| **Post-Quantum KEM** | Kyber512 (liboqs) / Mock-KEM fallback |
| **Messaging Protocol** | Custom binary protocol |
| **Networking** | TCP sockets |


# -------------------------------------------------------
# 1) Create & Activate Virtual Environment
# -------------------------------------------------------

```bash
python -m venv .venv
source .venv/Scripts/activate      # Windows (Git Bash)
```         

# -------------------------------------------------------
# 2) Upgrade pip
# -------------------------------------------------------
```bash
pip install --upgrade pip
```

# -------------------------------------------------------
# 3) Install Core Requirements
# -------------------------------------------------------
```bash
pip install sqlalchemy
pip install pymysql
pip install python-dotenv
pip install cryptography
pip install pycryptodome
pip install pillow
```
# -------------------------------------------------------
# 4) Install Async Server + GUI Dependencies
# -------------------------------------------------------
```bash
pip install aiohttp
pip install websockets
pip install tkintertable   # optional (Tkinter helper libs)
```
# -------------------------------------------------------
# 5) Install liboqs (optional PQC backend)
# -------------------------------------------------------
```bash
pip install pyoqs || echo "Skipping pyoqs (optional for PQC)"
```
# -------------------------------------------------------
# 6) Install Testing Tools
# -------------------------------------------------------
```bash
pip install pytest
pip install pytest-asyncio
```
# -------------------------------------------------------

# 7) Verify Installation
# -------------------------------------------------------
```bash
python - << "EOF"
import sqlalchemy, pymysql, tkinter, cryptography
print("SQLAlchemy:", sqlalchemy.__version__)
print("PyMySQL OK")
print("Tkinter OK")
print("Crypto OK")
EOF
```

