# Backend/mock_kem.py
import os
import base64
from hashlib import sha256

def server_generate_keypair():
    # returns (pub, priv) for server role — mock bytes
    priv = os.urandom(48)
    pub = sha256(priv).digest()
    return base64.b64encode(pub).decode(), base64.b64encode(priv).decode()

def client_encapsulate(server_pub_b64):
    server_pub = base64.b64decode(server_pub_b64)
    # mock: produce ciphertext and shared_secret deterministically
    ct = os.urandom(64)
    shared = sha256(server_pub + ct).digest()
    return base64.b64encode(ct).decode(), base64.b64encode(shared).decode()

def server_decaps(priv_b64, client_ct_b64):
    priv = base64.b64decode(priv_b64)
    ct = base64.b64decode(client_ct_b64)
    shared = sha256(sha256(priv).digest() + ct).digest()
    return base64.b64encode(shared).decode()
