# app/domain/__init__.py

"""
Módulo principal para componentes do core da aplicação.

Este módulo exporta exceções, configurações e utilitários core.
"""

# Exportar todas as exceções para facilitar a importação
from app.domain.exceptions import (
    ALPException,
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    ResourceInactiveException,
    PermissionDeniedException,
    InvalidCredentialsException,
    DatabaseOperationException,
    InvalidInputException,
    CategoryException
)

# Exportar configurações
from app.adapters.configuration.config import settings
