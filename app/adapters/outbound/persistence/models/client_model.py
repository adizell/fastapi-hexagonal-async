# app/adapters/outbound/persistence/models/client_model.py

"""
Modelo de client para autenticação e acesso à API.

Este módulo define o modelo Client que representa aplicações
ou sistemas externos autorizados a acessar a API.
"""

from sqlalchemy import Column, BigInteger, String, Boolean, DateTime, func
from app.adapters.outbound.persistence.models.base_model import Base


class Client(Base):
    """
    Modelo que representa um client (aplicação/parceiro) que acessa a API.

    Um client é uma aplicação ou sistema externo autorizado a acessar
    a API com credenciais específicas.

    Attributes:
        id: Identificador único do client
        client_id: ID público do client (como username)
        client_secret: Hash da chave secreta (senha) do client
        is_active: Indica se o client está ativo
        created_at: Data e hora de criação
        updated_at: Data e hora da última atualização
    """
    __tablename__ = "clients"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    client_id = Column(String, unique=True, nullable=False, index=True)
    client_secret = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        """Representação em string do objeto Client."""
        return f"<Client(client_id={self.client_id}, active={self.is_active})>"
