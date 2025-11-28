from Backend.hash_utils import sha3_256, sha3_512, sha512, fingerprint


def test_hash_functions():
    data = b"hello"

    assert sha3_256(data) == sha3_256(data)
    assert sha3_512(data) == sha3_512(data)
    assert sha512(data) == sha512(data)

    fp = fingerprint(data)
    assert len(fp) == 16  # default 8 bytes → 16 hex chars
