# app/adapters/outbound/persistence/models/token_blacklist.py

"""
Modelo para blacklist de tokens.

Este módulo define o modelo usado para armazenar tokens revogados
ou expirados para prevenir sua reutilização.
"""

from sqlalchemy import Column, String, DateTime
from app.adapters.outbound.persistence.models.base_model import Base


class TokenBlacklist(Base):
    """
    Modelo para armazenar tokens revogados.

    Attributes:
        jti: JWT ID - identificador único do token
        expires_at: Data e hora de expiração do token
        revoked_at: Data e hora em que o token foi revogado
    """
    __tablename__ = "token_blacklist"

    jti = Column(String, primary_key=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=False)
