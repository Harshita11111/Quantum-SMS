import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Backend.message_service import send_message, get_messages


def test_send_and_receive_messages():
    sender = 1
    receiver = 2
    text = "Hello PQC!"

    ok, _ = send_message(sender, receiver, text)
    assert ok

    msgs = get_messages(receiver)
    assert len(msgs) > 0
    assert msgs[-1].ciphertext is not None
