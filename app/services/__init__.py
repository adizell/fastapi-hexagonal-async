# app/services/__init__.py

"""
Módulo de serviços da aplicação.

Este pacote contém os serviços que implementam a lógica de negócios
da aplicação, organizados de acordo com os domínios funcionais.
"""

# Exportar classes de serviço para facilitar importações
from app.services.base_service import BaseService
from app.services.client_service import ClientService
from app.services.user_service import UserService

# Exportar todos os serviços
__all__ = [
    "BaseService",
    "ClientService",
    "UserService",
]
