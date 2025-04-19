# app/adapters/outbound/security/auth_user_manager.py (async version)

import uuid
from datetime import datetime, timedelta

from jose import jwt, JWTError
from fastapi import HTTPException, status
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.configuration.config import settings
from app.adapters.outbound.persistence.repositories.token_repository import token_repository

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
DEFAULT_EXPIRES_MIN = settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS


class UserAuthManager:
    """
    JWT authentication manager for users.
    """

    crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    async def hash_password(cls, password: str) -> str:
        """Return the hash of a plain text password."""
        return cls.crypt_context.hash(password)

    @classmethod
    async def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """Verify if the plain text password matches the stored hash."""
        return cls.crypt_context.verify(plain_password, hashed_password)

    @classmethod
    async def create_access_token(cls, subject: str, expires_delta: timedelta = None) -> str:
        """
        Create a JWT access token for the authenticated user.

        - subject: typically the user's UUID.
        - expires_delta: custom expiration time.
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=DEFAULT_EXPIRES_MIN)

        expire = datetime.utcnow() + expires_delta
        jti = str(uuid.uuid4())

        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": "user",
            "jti": jti,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    async def verify_access_token(cls, token: str, db: AsyncSession = None) -> dict:
        """
        Verify and decode a JWT access token.
        Also checks if it was revoked (blacklist).
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            if payload.get("type") != "user":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: incorrect type."
                )

            # If session provided, check blacklist
            if db and payload.get("jti") and await token_repository.is_blacklisted(db, payload["jti"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token revoked."
                )

            return payload

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token."
            )

    @classmethod
    async def create_refresh_token(cls, subject: str, token_id: str, expires_delta: timedelta = None) -> str:
        """
        Create a JWT refresh token.

        - subject: typically the user's UUID.
        - token_id: unique identifier for blacklisting.
        - expires_delta: custom expiration time.
        """
        if expires_delta is None:
            # Default: configured refresh days
            expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": "refresh",
            "jti": token_id,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    async def verify_refresh_token(cls, token: str) -> dict:
        """
        Verify and decode a JWT refresh token.
        Returns the payload if valid.
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token."
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token."
            )
