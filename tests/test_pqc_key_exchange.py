from Backend.pqc_key_exchange import PQCKeyExchange


def test_pqc_key_exchange():
    pqc = PQCKeyExchange()

    pk = pqc.generate_keypair()
    ct, ss1 = pqc.encapsulate(pk)
    ss2 = pqc.decapsulate(ct)

    assert ss1 == ss2, "Shared secrets must match for KEM"
