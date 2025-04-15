# app/adapters/outbound/persistence/models/user_access_group.py

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import BigInteger
from app.adapters.outbound.persistence.models.base_model import Base

########################################################################
# Tabela de associação many-to-many entre usuários e grupos
########################################################################

user_access_groups = Table(
    "user_access_groups",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", BigInteger, ForeignKey("auth_group.id", ondelete="CASCADE"), primary_key=True),
)
