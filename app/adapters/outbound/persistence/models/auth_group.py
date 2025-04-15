# app/adapters/outbound/persistence/models/auth_group.py

"""
Modelo de grupo de permissões.

Este módulo define o modelo de grupo que agrupa permissões
para facilitar o gerenciamento de acesso.
"""

from sqlalchemy import Column, BigInteger, String
from sqlalchemy.orm import relationship
from app.adapters.outbound.persistence.models.base_model import Base


class AuthGroup(Base):
    """
    Modelo de grupo de permissões.

    Representa um conjunto de permissões que podem ser atribuídas
    a usuários, facilitando o gerenciamento de acesso.

    Attributes:
        id: Identificador único do grupo
        name: Nome do grupo (ex: "admin", "user")
        permissions: Relação com as permissões associadas ao grupo
    """
    __tablename__ = "auth_group"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    name = Column(String(150), unique=True, nullable=False, index=True)

    # Relação com permissões via tabela de associação
    permissions = relationship(
        "AuthPermission",
        secondary="auth_group_permissions",
        back_populates="groups",
        lazy="joined"  # Otimiza queries carregando dados em join
    )

    def __repr__(self) -> str:
        """Representação em string do objeto AuthGroup."""
        return f"<AuthGroup(name={self.name})>"

    def has_permission(self, codename: str) -> bool:
        """
        Verifica se o grupo possui uma permissão específica pelo codename.

        Args:
            codename: Código da permissão a verificar

        Returns:
            True se o grupo tiver a permissão, False caso contrário
        """
        return any(perm.codename == codename for perm in self.permissions)
