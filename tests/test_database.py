from Backend.database import engine, Base
from sqlalchemy import inspect


def test_tables_exist():
    inspector = inspect(engine)

    tables = inspector.get_table_names()

    assert "users" in tables
    assert "messages" in tables
    assert "keystore" in tables
