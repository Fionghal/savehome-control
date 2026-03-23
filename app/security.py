from __future__ import annotations

from passlib.context import CryptContext

# pbkdf2_sha256 je stabilnější napříč Linux/Windows než bcrypt backend.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
