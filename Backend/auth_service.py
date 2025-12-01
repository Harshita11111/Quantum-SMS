# Backend/auth_service.py
# Simple explanation: Handles sign up and login. When a user registers, we hash their password and create a Kyber keypair stored in KeyStorage. On login we verify password and return the user ID.

from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash

from .database import SessionLocal
from .models import User
from .key_storage_service import create_keypair_for_user


# ---------------------------
# USER REGISTRATION
# ---------------------------
def register_user(username: str, email: str, password: str):
    db: Session = SessionLocal()
    try:
        # Check if username already exists
        if db.query(User).filter(User.username == username).first():
            return False, "username_exists"

        # Hash password securely
        hashed = generate_password_hash(password)

        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=hashed
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Generate Kyber keypair for user
        create_keypair_for_user(db, user.id)

        return True, "registered_successfully"

    except Exception as e:
        db.rollback()
        return False, f"error: {e}"

    finally:
        db.close()


# ---------------------------
# USER LOGIN
# ---------------------------
def login_user(username: str, password: str):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            return False, "user_not_found"

        # Validate password
        if not check_password_hash(user.password_hash, password):
            return False, "invalid_credentials"

        return True, user.id

    finally:
        db.close()
