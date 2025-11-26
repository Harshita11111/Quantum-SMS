# qsms/database/db_test.py
"""
Full module tests for QSMS Database.

Run from project root:
    pytest -q qsms/database/db_test.py
"""

from __future__ import annotations

# --- ensure we can import 'qsms' no matter where pytest is launched from -----
try:
    import qsms  # noqa: F401
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(PROJECT_ROOT))

import os
import importlib
import pytest

# -----------------------------------------------------------------------------
# Test environment: force in-memory SQLite; reload modules to bind to this URL
# -----------------------------------------------------------------------------

@pytest.fixture(scope="session")
def db_env():
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"

    import qsms.database.db_config as db_config
    import qsms.database.models as models

    importlib.reload(db_config)
    importlib.reload(models)

    engine = db_config.get_engine()
    models.create_all(engine)

    return {"db_config": db_config, "models": models}


@pytest.fixture()
def clean_schema(db_env):
    db_config = db_env["db_config"]
    models = db_env["models"]
    engine = db_config.get_engine()
    models.Base.metadata.drop_all(engine)
    models.Base.metadata.create_all(engine)
    return db_env


# -----------------------------------------------------------------------------
# Imports for APIs under test
# -----------------------------------------------------------------------------

from qsms.database import db_init
from qsms.database.user_management import DBUserStore
from qsms.database.key_storage import (
    save_public_key,
    get_public_keys,
    get_latest_public_key,
    save_wrapped_session_key,
    get_latest_wrapped_session_key,
    get_wrapped_session_keys,
)
from qsms.database.message_storage import (
    save_message,
    fetch_inbox,
    fetch_outbox,
    fetch_conversation,
    mark_delivered,
    count_unread,
    delete_message,
    purge_user,
)


# -----------------------------------------------------------------------------
# db_config / models / db_init
# -----------------------------------------------------------------------------

def test_engine_sqlite_and_schema_via_models(db_env):
    db_config = db_env["db_config"]
    models = db_env["models"]

    eng = db_config.get_engine()
    assert eng.url.get_backend_name() == "sqlite"

    # idempotent
    models.create_all(eng)
    models.create_all(eng)


def test_db_init_cli_paths(clean_schema):
    assert db_init.main(["--recreate"]) == 0
    assert db_init.main(["--seed", "seed_user", "seed_pw"]) == 0

    store = DBUserStore()
    assert store.get("seed_user") is not None


# -----------------------------------------------------------------------------
# user_management
# -----------------------------------------------------------------------------

def test_user_crud_verify_update_audit_delete(clean_schema):
    store = DBUserStore()

    store.add_user("alice", "correct horse battery staple")
    store.add_user("bob", "bobs_password")

    rec = store.get("alice")
    assert rec and rec.username == "alice"
    assert isinstance(rec.pbkdf2_iter, int)
    assert rec.salt_b64 and rec.password_hash_b64

    assert store.verify_credentials("alice", "correct horse battery staple")
    assert not store.verify_credentials("alice", "wrong")
    assert not store.verify_credentials("nobody", "irrelevant")

    store.record_login("alice", ok=True, ip="127.0.0.1")

    assert store.update_password("alice", "new strong password", pbkdf2_iter=300_000)
    assert store.verify_credentials("alice", "new strong password")
    assert not store.verify_credentials("alice", "correct horse battery staple")

    assert store.delete_user("bob")
    assert store.get("bob") is None


def test_user_delete_cascades_keys(clean_schema):
    from qsms.database.models import Key, User
    from qsms.database.db_config import session_scope

    store = DBUserStore()
    store.add_user("charlie", "pw")

    save_public_key("charlie", b"PK1", key_type="kyber-pk")

    with session_scope() as s:
        u = s.query(User).filter_by(username="charlie").one()
        assert s.query(Key).filter_by(user_id=u.id).count() == 1

    assert store.delete_user("charlie")
    with session_scope() as s:
        assert s.query(User).filter_by(username="charlie").one_or_none() is None
        assert s.query(Key).count() == 0


# -----------------------------------------------------------------------------
# key_storage
# -----------------------------------------------------------------------------

def test_key_storage_public_and_wrapped(clean_schema):
    store = DBUserStore()
    store.add_user("alice", "pw")

    # public key default device
    save_public_key("alice", b"PK1")
    assert get_latest_public_key("alice") == b"PK1"

    # replace default
    save_public_key("alice", b"PK2", replace=True)
    assert get_latest_public_key("alice") == b"PK2"

    # device-specific
    save_public_key("alice", b"DEV_PK", device_id="laptop-01")
    keys = get_public_keys("alice", device_id="laptop-01")
    assert len(keys) == 1 and keys[0].public_key == b"DEV_PK"

    # wrapped session keys
    save_wrapped_session_key("alice", b"WRAP1", device_id="laptop-01")
    save_wrapped_session_key("alice", b"WRAP2", device_id="laptop-01")
    assert get_latest_wrapped_session_key("alice", device_id="laptop-01") == b"WRAP2"
    assert set(get_wrapped_session_keys("alice", device_id="laptop-01")) == {b"WRAP1", b"WRAP2"}


# -----------------------------------------------------------------------------
# message_storage
# -----------------------------------------------------------------------------

def test_message_flow_inbox_outbox_conversation_pagination(clean_schema):
    store = DBUserStore()
    store.add_user("alice", "a")
    store.add_user("bob", "b")

    m1 = save_message("alice", "bob", b"n1", b"c1", b"a1")
    _m2 = save_message("bob", "alice", b"n2", b"c2")
    m3 = save_message("alice", "bob", b"n3", b"c3")

    # unread for Bob (two to Bob, both undelivered)
    assert count_unread("bob") == 2

    # inbox newest-first
    inbox_bob = fetch_inbox("bob", include_delivered=True, newest_first=True)
    assert [m.ciphertext for m in inbox_bob][:2] == [b"c3", b"c1"]

    # mark delivered for first
    assert mark_delivered(m1)
    assert count_unread("bob") == 1

    # outbox + conversation (deterministic ordering)
    out_alice = fetch_outbox("alice")
    assert {m.ciphertext for m in out_alice} >= {b"c1", b"c3"}

    conv = fetch_conversation("alice", "bob", chronological=True)
    assert [m.ciphertext for m in conv] == [b"c1", b"c2", b"c3"]

    # pagination ascending
    page1 = fetch_inbox("bob", include_delivered=True, newest_first=False, limit=1, offset=0)
    page2 = fetch_inbox("bob", include_delivered=True, newest_first=False, limit=1, offset=1)
    assert [m.ciphertext for m in page1] == [b"c1"]
    assert [m.ciphertext for m in page2] == [b"c3"]

    # delete + purge
    assert delete_message(m3)
    after = fetch_inbox("bob", include_delivered=True)
    assert b"c3" not in [m.ciphertext for m in after]

    purged = purge_user("alice")
    assert purged >= 1
    assert fetch_outbox("alice") == []


def test_inbox_filters_unread_only(clean_schema):
    store = DBUserStore()
    store.add_user("alice", "a")
    store.add_user("bob", "b")

    a = save_message("alice", "bob", b"na", b"pa")
    b = save_message("alice", "bob", b"nb", b"pb")
    mark_delivered(a)

    unread_only = fetch_inbox("bob", include_delivered=False)
    assert [m.ciphertext for m in unread_only] == [b"pb"]
