# app/adapters/outbound/security/token_store.py

from pydantic import BaseModel
from typing import List


class StaticClientToken(BaseModel):
    hashed_password: str


class TokenStore:
    # Lista fixa de tokens autorizados (sem username agora)
    authorized_tokens: List[StaticClientToken] = [
        StaticClientToken(
            hashed_password="$2b$12$BEVPIjnVmniBJn28JYsEB.shiVlSppkTgsr9RaXajE6c9Ln48gj/q"
        )
    ]

    @classmethod
    def validate(cls, plain_password: str, crypt_context) -> bool:
        for token in cls.authorized_tokens:
            if crypt_context.verify(plain_password, token.hashed_password):
                return True
        return False

# Como usar:
# python app/security/token_gerar.py
