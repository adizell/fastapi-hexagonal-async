# app/domain/exceptions.py

"""
Exceções personalizadas para o domínio.

Este módulo define exceções específicas do domínio, sem dependências de frameworks.
"""

from typing import Any, Dict, Optional


class DomainException(Exception):
    """
    Exceção base para todas as exceções do domínio.
    """

    def __init__(
            self,
            message: str,
            internal_code: Optional[str] = None,
            details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.internal_code = internal_code
        self.details = details or {}


class ResourceNotFoundException(DomainException):
    """Recurso não encontrado."""

    def __init__(self, message: str = "Recurso não encontrado", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            message=f"{message}{resource_info}",
            internal_code="RESOURCE_NOT_FOUND"
        )


class ResourceAlreadyExistsException(DomainException):
    """Recurso já existe."""

    def __init__(self, message: str = "Recurso já existe", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            message=f"{message}{resource_info}",
            internal_code="RESOURCE_ALREADY_EXISTS"
        )


class PermissionDeniedException(DomainException):
    """Permissão negada."""

    def __init__(self, message: str = "Permissão negada", permission: Optional[str] = None):
        permission_info = f" (Permissão necessária: {permission})" if permission else ""
        super().__init__(
            message=f"{message}{permission_info}",
            internal_code="PERMISSION_DENIED"
        )


class InvalidCredentialsException(DomainException):
    """Credenciais inválidas."""

    def __init__(self, message: str = "Credenciais inválidas"):
        super().__init__(
            message=message,
            internal_code="INVALID_CREDENTIALS"
        )


class DatabaseOperationException(DomainException):
    """Erro na operação de banco de dados."""

    def __init__(self, message: str = "Erro ao executar operação no banco de dados",
                 original_error: Optional[Exception] = None):
        error_info = f": {str(original_error)}" if original_error else ""
        super().__init__(
            message=f"{message}{error_info}",
            internal_code="DATABASE_OPERATION_ERROR"
        )


class InvalidInputException(DomainException):
    """Dados de entrada inválidos."""

    def __init__(self, message: str = "Dados de entrada inválidos", fields: Optional[Dict[str, str]] = None):
        field_errors = ""
        if fields:
            field_errors = ": " + ", ".join([f"{field}: {error}" for field, error in fields.items()])
        super().__init__(
            message=f"{message}{field_errors}",
            internal_code="INVALID_INPUT"
        )


class ResourceInactiveException(DomainException):
    """Recurso encontrado, mas está inativo."""

    def __init__(self, message: str = "Recurso está inativo", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            message=f"{message}{resource_info}",
            internal_code="RESOURCE_INACTIVE"
        )
