# app/adapters/outbound/security/auth_client_manager.py (async version)

from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status
from passlib.context import CryptContext

from app.adapters.configuration.config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
DEFAULT_EXPIRES_DAYS = settings.ACCESS_TOKEN_CLIENT_EXPIRE_DIAS


class ClientAuthManager:
    """
    Authentication manager for JWT tokens of clients (authorized applications).
    """

    crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    async def create_client_token(cls, subject: str, expires_delta: timedelta = None) -> str:
        """
        Create a JWT token for the client with 'sub' equal to subject and type "client".
        """
        if expires_delta is None:
            expires_delta = timedelta(days=DEFAULT_EXPIRES_DAYS)

        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": "client",
        }

        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    async def verify_client_token(cls, token: str) -> dict:
        """
        Decode and validate the client's JWT token.

        Returns the payload if the token is valid and of type "client".
        Raises HTTPException if invalid or expired.
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "client":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid client token: incorrect type.",
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired client token.",
            )

    @classmethod
    async def hash_password(cls, password: str) -> str:
        """
        Generate secure password hash for storage in the database.
        """
        return cls.crypt_context.hash(password)

    @classmethod
    async def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """
        Compare plain text password with stored hash.
        """
        return cls.crypt_context.verify(plain_password, hashed_password)
