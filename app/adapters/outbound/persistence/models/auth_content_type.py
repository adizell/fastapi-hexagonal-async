# app/adapters/outbound/persistence/models/auth_content_type.py

"""
Modelo de tipo de conteúdo para sistema de permissões.

Este módulo define o modelo que representa tipos de conteúdo
para o sistema de permissões, agrupando permissões relacionadas.
"""

from sqlalchemy import Column, BigInteger, String, Index
from sqlalchemy.orm import relationship
from app.adapters.outbound.persistence.models.base_model import Base


class AuthContentType(Base):
    """
    Modelo de tipo de conteúdo para sistema de permissões.

    Representa uma categoria ou tipo de conteúdo ao qual permissões
    podem ser associadas, como 'user', 'pet', 'specie', etc.

    Attributes:
        id: Identificador único do tipo de conteúdo
        app_label: Nome da aplicação/domínio (ex: pet, specie, user)
        model: Nome da ação/entidade (ex: create, list, update)
        permissions: Relação com as permissões associadas a este tipo
    """
    __tablename__ = "auth_content_type"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    app_label = Column(String(100), nullable=False, index=True,
                       doc="Nome da aplicação ou domínio (ex: pet, specie)")
    model = Column(String(100), nullable=False, index=True,
                   doc="Ação ou entidade (ex: create, list, update)")

    # Relação com permissões
    permissions = relationship("AuthPermission", back_populates="content_type", cascade="all, delete-orphan")

    # Índice composto para app_label e model
    __table_args__ = (
        Index("idx_content_type_app_model", "app_label", "model"),
    )

    def __repr__(self) -> str:
        """Representação em string do objeto AuthContentType."""
        return f"<AuthContentType(app_label='{self.app_label}', model='{self.model}')>"
