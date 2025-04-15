# app/application/use_cases/__init__.py

"""
Módulo de serviços da aplicação.

Este pacote contém os serviços que implementam a lógica de negócios
da aplicação, organizados de acordo com os domínios funcionais.
"""

# Exportar classes de serviço para facilitar importações
from app.application.use_cases.base_use_cases import BaseService
from app.application.use_cases.client_use_cases import ClientService
from app.application.use_cases.user_use_cases import UserService

# Exportar todos os serviços
__all__ = [
    "BaseService",
    "ClientService",
    "UserService",
]
