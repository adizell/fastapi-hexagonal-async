# app/adapters/outbound/persistence/repositories/__init__.py (async version)

"""
CRUD (Create, Read, Update, Delete) module.

This module exports classes and instances of the repositories CRUD
for different system entities, implementing the Repository pattern.
"""

# Import CRUD classes
from app.adapters.outbound.persistence.repositories.base_repository import AsyncCRUDBase
from app.adapters.outbound.persistence.repositories.user_repository import user_repository
from app.adapters.outbound.persistence.repositories.client_repository import client_repository
from app.adapters.outbound.persistence.repositories.token_repository import token_repository

# Import singleton CRUD instances
from app.adapters.outbound.persistence.repositories.user_repository import AsyncUserCRUD
from app.adapters.outbound.persistence.repositories.client_repository import AsyncClientCRUD

# Export all classes and instances
__all__ = [
    # Classes
    "AsyncCRUDBase",
    "AsyncUserCRUD",
    "AsyncClientCRUD",

    # Instances
    "user_repository",
    "client_repository",
    "token_repository",
]
