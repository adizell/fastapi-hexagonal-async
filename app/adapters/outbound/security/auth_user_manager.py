# app/adapters/outbound/security/auth_user_manager.py

import uuid
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status
from passlib.context import CryptContext

from app.adapters.configuration.config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
DEFAULT_EXPIRES_MIN = settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS


class UserAuthManager:
    """
    Gerenciador de autenticação JWT para usuários.
    """

    crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hash_password(cls, password: str) -> str:
        return cls.crypt_context.hash(password)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return cls.crypt_context.verify(plain_password, hashed_password)

    @classmethod
    def create_access_token(cls, subject: str, expires_delta: timedelta = None) -> str:
        """
        Cria um token JWT para o usuário autenticado.

        - `subject`: normalmente o UUID do usuário.
        - `expires_delta`: tempo de expiração customizado.
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=DEFAULT_EXPIRES_MIN)

        expire = datetime.utcnow() + expires_delta
        token_id = str(uuid.uuid4())

        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": "user",
            "jti": token_id,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    def verify_access_token(cls, token: str, db=None) -> dict:
        from app.adapters.outbound.persistence.repositories.token_repository import token_repository

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "user":
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido: tipo incorreto")
            if db and payload.get("jti") and token_repository.is_blacklisted(db, payload["jti"]):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revogado")
            return payload
        except JWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido ou expirado")

    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Retorna o hash da senha em texto plano.
        """
        return cls.crypt_context.hash(password)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """
        Verifica se a senha em texto corresponde ao hash armazenado.
        """
        return cls.crypt_context.verify(plain_password, hashed_password)

    @classmethod
    def create_refresh_token(cls, subject: str, token_id: str, expires_delta: timedelta = None) -> str:
        if expires_delta is None:
            expires_delta = timedelta(days=settings.ACCESS_TOKEN_CLIENT_EXPIRE_DIAS)
        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": "refresh",
            "jti": token_id,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    def verify_refresh_token(cls, token: str) -> dict:
        """
        Verifica e decodifica um refresh token JWT.

        Retorna o payload se for válido.
        Lança HTTP 401 se o token for inválido, expirado ou incorreto.
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "refresh":
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token de refresh inválido")
            return payload
        except JWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token inválido ou expirado")
