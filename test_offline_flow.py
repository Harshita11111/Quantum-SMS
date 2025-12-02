# tests/test_offline_flow.py
from Backend.database import Base, engine
from Backend.key_storage_service import ensure_keypair_for_user, get_private_key_for_user
from Backend.message_service import send_message, get_messages_for_user, retrieve_and_decrypt_for_user

# Ensure tables exist (run once)
Base.metadata.create_all(bind=engine)

# Test params
sender = 1
receiver = 2
plaintext = b"Hello offline friend!"

# Ensure keypairs for users exist
ensure_keypair_for_user(sender)
ensure_keypair_for_user(receiver)

# Send encrypted message (stores kim_ct + nonce + ciphertext)
ok, res = send_message(sender, receiver, plaintext)
print("send_message:", ok, res)

msgs = get_messages_for_user(receiver)
print("messages count:", len(msgs))
for m in msgs:
    print("stored msg id:", m.id, "kem_ct_len:", len(m.kem_ct), "cipher_len:", len(m.ciphertext))

# Attempt to decrypt
decrypted = retrieve_and_decrypt_for_user(receiver)
print("decrypted:", decrypted)
