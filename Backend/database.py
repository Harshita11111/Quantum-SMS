# database.py
# Simple explanation: This is the standard SQLAlchemy setup. SessionLocal() gives you a DB session to query/commit. Base is the parent class for models.
# What to say: “It’s the DB setup that every other backend file imports to talk to MySQL.”

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .db_config import DB_URL

engine = create_engine(DB_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
