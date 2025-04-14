# app/crud/__init__.py

"""
Módulo de CRUD (Create, Read, Update, Delete).

Este módulo exporta classes e instâncias dos repositórios CRUD
para as diferentes entidades do sistema, implementando o padrão Repository.
"""

# Importar classes CRUD
from app.crud.base import CRUDBase
from app.crud.user_crud import UserCRUD
from app.crud.client_crud import ClientCRUD

# Importar instâncias singleton do CRUD
from app.crud.user_crud import user
from app.crud.client_crud import client

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
