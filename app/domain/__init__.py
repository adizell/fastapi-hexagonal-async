# app/domain/__init__.py

"""
Módulo principal para componentes do domínio da aplicação.

Este módulo exporta exceções, configurações e utilitários do domínio.
"""

# Exportar todas as exceções para facilitar a importação
from app.domain.exceptions import (
    DomainException,               # Exceção base pura do domínio
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    ResourceInactiveException,
    PermissionDeniedException,
    InvalidCredentialsException,
    DatabaseOperationException,
    InvalidInputException,
)

# Exportar configurações
from app.adapters.configuration.config import settings
