from Backend.auth_service import register_user, login_user


def test_user_registration_and_login():
    username = "test_user"
    email = "test@example.com"
    password = "password123"

    ok, msg = register_user(username, email, password)
    assert ok

    ok, uid = login_user(username, password)
    assert ok
    assert isinstance(uid, int)
