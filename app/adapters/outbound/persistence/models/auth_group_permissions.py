# app/adapters/outbound/persistence/models/auth_group_permissions.py

"""
Tabela de associação entre grupos e permissões.

Este módulo define a tabela de associação many-to-many
entre grupos (AuthGroup) e permissões (AuthPermission).
"""

from sqlalchemy import Table, Column, BigInteger, ForeignKey, UniqueConstraint
from app.adapters.outbound.persistence.models.base_model import Base

# Tabela de associação entre grupos e permissões
auth_group_permissions = Table(
    "auth_group_permissions",
    Base.metadata,

    # Colunas
    Column("group_id", BigInteger, ForeignKey("auth_group.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", BigInteger, ForeignKey("auth_permission.id", ondelete="CASCADE"), primary_key=True),

    # Índices e constraints
    UniqueConstraint("group_id", "permission_id", name="uq_group_permission"),

    # Comentário da tabela
    comment="Tabela de associação many-to-many entre grupos e permissões"
)
