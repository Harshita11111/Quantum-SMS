from network.client import QSMSClient

try:
    c = QSMSClient("127.0.0.1", 5000)
    c.connect()
    print("[TEST] Connected OK")

    c.authenticate("testuser", "testpass")
    print("[TEST] Authentication OK")

    c.key_exchange()
    print("[TEST] KEM OK")

except Exception as e:
    print("[TEST ERROR]", e)
