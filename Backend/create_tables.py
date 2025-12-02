# create_tables.py
# Simple explanation: Calls Base.metadata.create_all(bind=engine) to create tables if missing.
from .database import engine
from .models import Base

def create_all():
    Base.metadata.create_all(bind=engine)
    print("Tables created (if not exist)")

if __name__ == "__main__":
    create_all()
