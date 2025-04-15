# app/adapters/outbound/persistence/repositories/__init__.py

"""
Módulo de CRUD (Create, Read, Update, Delete).

Este módulo exporta classes e instâncias dos repositórios CRUD
para as diferentes entidades do sistema, implementando o padrão Repository.
"""

# Importar classes CRUD
from app.adapters.outbound.persistence.repositories.base_repository import CRUDBase
from app.adapters.outbound.persistence.repositories.user_repository import UserCRUD
from app.adapters.outbound.persistence.repositories.client_repository import ClientCRUD

# Importar instâncias singleton do CRUD
from app.adapters.outbound.persistence.repositories.user_repository import user
from app.adapters.outbound.persistence.repositories.client_repository import client

# Exportar todas as classes e instâncias
__all__ = [
    # Classes
    "CRUDBase",
    "UserCRUD",
    "ClientCRUD",

    # Instâncias
    "user",
    "client",
]
