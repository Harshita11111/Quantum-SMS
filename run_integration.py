# run_integration.py — integration test for qsms package
import socket
import sys
import os

from qsms import CryptoManager, derive_aes_key_from_handshake, encrypt_aes_gcm, decrypt_aes_gcm, send_frame, recv_frame

def socketpair_fallback():
    """Return a pair of connected sockets. Prefer socket.socketpair if available."""
    if hasattr(socket, "socketpair"):
        return socket.socketpair()
    # Windows fallback: create a listening socket and connect to it
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    addr, port = srv.getsockname()
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.settimeout(3.0)
    cli.connect((addr, port))
    srv_conn, _ = srv.accept()
    srv.close()
    return (srv_conn, cli)

def main():
    print("[*] Starting QSMS integration test...")

    # 1) Server generates keypair (receiver)
    server = CryptoManager()
    try:
        pk = server.generate_keys()
    except Exception as e:
        print("FAILED: generating keys. Ensure liboqs/python binding is installed and available.")
        raise

    # 2) Client encapsulates to server
    client = CryptoManager()
    ct, ss_client = client.encapsulate(pk)
    print("[*] Client encapsulated. ct len:", len(ct))

    # 3) Server decapsulates
    ss_server = server.decapsulate(ct)
    print("[*] Server decapsulated. shared secret lengths:", len(ss_client), len(ss_server))

    # 4) Both derive identical AES key & get KeySchedule (salt/aad)
    aes_key_client, ks_client = derive_aes_key_from_handshake(pk, ct, ss_client)
    aes_key_server, ks_server = derive_aes_key_from_handshake(pk, ct, ss_server)

    assert ks_client.salt == ks_server.salt, "salt mismatch"
    assert ks_client.aad == ks_server.aad, "aad mismatch"
    assert aes_key_client == aes_key_server, "derived AES key mismatch"

    print("[+] Derived AES key equal. AAD fingerprint (hex):", ks_client.salt.hex()[:16])

    # 5) Client encrypts a message using aes_utils encrypt_aes_gcm (nonce + ciphertext(tag))
    plaintext = b"Hello Quantum-SMS! This is a test."
    enc = encrypt_aes_gcm(plaintext, aes_key_client, associated_data=ks_client.aad)
    nonce = enc["nonce"]
    ciphertext = enc["ciphertext"]
    print("[*] Client encrypted message. nonce len:", len(nonce), "ciphertext len:", len(ciphertext))

    # 6) Simulate sending ct (kem_ct) and the encrypted message over a framed socket
    s1, s2 = socketpair_fallback()
    try:
        # Send KEM ct as first frame so receiver can decapsulate (in real protocol this is done earlier)
        send_frame(s1, ct)
        send_frame(s1, nonce + ciphertext)  # send nonce||ciphertext (ciphertext includes tag)

        # Server reads frames
        rec_ct = recv_frame(s2)
        rec_blob = recv_frame(s2)

        # ensure rec_ct == ct
        assert rec_ct == ct
        recv_nonce = rec_blob[:12]
        recv_ciphertext = rec_blob[12:]
        # decrypt on server side using derived key and same AAD
        decrypted = decrypt_aes_gcm(recv_nonce, recv_ciphertext, aes_key_server, associated_data=ks_server.aad)
        assert decrypted == plaintext
        print("[+] Decrypted message on server:", decrypted.decode())
    finally:
        s1.close(); s2.close()

    print("[*] Integration test completed successfully.")

if __name__ == "__main__":
    main()
