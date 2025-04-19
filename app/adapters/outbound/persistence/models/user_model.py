# app/adapters/outbound/persistence/models/user_model.py

"""
Modelo de usuário e associações relacionadas.

Este módulo define o modelo de usuário e suas tabelas de associação
com grupos e permissões, centralizando toda a lógica relacionada
a usuários em um único arquivo.
"""

from sqlalchemy import (
    Column,
    Boolean,
    String,
    DateTime,
    func,
    Table,
    ForeignKey,
    BigInteger
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.adapters.outbound.persistence.models.base_model import Base

# Tabela de associação many-to-many entre usuários e grupos
user_access_groups = Table(
    "user_access_groups",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", BigInteger, ForeignKey("auth_group.id", ondelete="CASCADE"), primary_key=True),
)

# Tabela de associação many-to-many entre usuários e permissões diretas
user_access_permission = Table(
    "user_access_permission",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", BigInteger, ForeignKey("auth_permission.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    """
    Modelo de usuário do sistema.

    Representa os usuários que podem acessar o sistema,
    com informações de autenticação e controle de acesso.

    Attributes:
        id: Identificador único do usuário (UUID)
        email: Email do usuário (utilizado para login)
        password: Hash da senha do usuário
        is_active: Indica se o usuário está ativo
        is_superuser: Indica se o usuário é um superusuário com acesso total
        created_at: Data e hora de criação
        updated_at: Data e hora da última atualização
        groups: Grupos de permissão aos quais o usuário pertence
        permissions: Permissões individuais atribuídas diretamente ao usuário
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Relação many-to-many com grupos
    groups = relationship(
        "AuthGroup",
        secondary=user_access_groups,
        backref="users",
        lazy="joined"  # Para carregar os grupos sempre que carregar um usuário
    )

    # Relação many-to-many com permissões individuais
    permissions = relationship(
        "AuthPermission",
        secondary=user_access_permission,
        backref="users",
        lazy="joined"  # Para carregar as permissões sempre que carregar um usuário
    )

    def __repr__(self) -> str:
        """Representação em string do objeto User."""
        return f"<User(email={self.email}, active={self.is_active})>"

    def has_permission(self, permission_codename: str) -> bool:
        """
        Verifica se o usuário possui uma permissão específica.

        A permissão pode vir de seus grupos ou ser atribuída diretamente.

        Args:
            permission_codename: Código da permissão a verificar

        Returns:
            True se o usuário tiver a permissão, False caso contrário
        """
        # Superusuários têm todas as permissões
        if self.is_superuser:
            return True

        # Verificar permissões atribuídas diretamente
        if any(perm.codename == permission_codename for perm in self.permissions):
            return True

        # Verificar permissões de grupos
        for group in self.groups:
            if any(perm.codename == permission_codename for perm in group.permissions):
                return True

        return False
