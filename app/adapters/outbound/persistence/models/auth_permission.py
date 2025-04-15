# app/adapters/outbound/persistence/models/auth_permission.py

"""
Modelo de permissão para controle de acesso.

Este módulo define o modelo de permissão utilizado no sistema
de controle de acesso baseado em permissões e grupos.
"""

from sqlalchemy import BigInteger, String, ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.adapters.outbound.persistence.models.base_model import Base


class AuthPermission(Base):
    """
    Modelo de permissão para controle de acesso.

    Representa uma permissão específica que pode ser atribuída
    diretamente a um usuário ou a um grupo.

    Attributes:
        id: Identificador único da permissão
        name: Nome legível da permissão (ex: "Can list_species")
        codename: Código único que identifica a permissão (ex: "list_species")
        content_type_id: ID do tipo de conteúdo associado
        content_type: Relação com o tipo de conteúdo
        groups: Grupos que possuem esta permissão
    """
    __tablename__ = "auth_permission"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    codename: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    content_type_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("auth_content_type.id"), nullable=False)

    # Relações
    content_type = relationship("AuthContentType", back_populates="permissions", lazy="joined")
    groups = relationship("AuthGroup", secondary="auth_group_permissions", back_populates="permissions")

    def __repr__(self) -> str:
        """Representação em string do objeto AuthPermission."""
        return f"<AuthPermission(codename={self.codename})>"
