# app/adapters/outbound/security/auth_client_manager.py

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
    Gerenciador de autenticação para tokens JWT de clients (aplicações autorizadas).
    """

    crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def create_client_token(cls, subject: str, expires_delta: timedelta = None) -> str:
        """
        Cria um token JWT para o client com 'sub' igual ao subject e tipo "client".
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
    def verify_client_token(cls, token: str) -> dict:
        """
        Decodifica e valida o token JWT do client.

        Retorna o payload se o token for válido e do tipo "client".
        Lança HTTPException se inválido ou expirado.
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "client":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token do client inválido: tipo incorreto.",
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token do client inválido ou expirado.",
            )

    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Gera hash seguro de senha para storage no banco.
        """
        return cls.crypt_context.hash(password)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """
        Compara senha em texto com o hash armazenado.
        """
        return cls.crypt_context.verify(plain_password, hashed_password)
