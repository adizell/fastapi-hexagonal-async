# app/core/__init__.py

"""
Módulo principal para componentes do core da aplicação.

Este módulo exporta exceções, configurações e utilitários core.
"""

# Exportar todas as exceções para facilitar a importação
from app.core.exceptions import (
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
from app.core.config import settings
