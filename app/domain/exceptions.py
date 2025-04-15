# app/domain/exceptions.py

"""
Exceções personalizadas para o aplicativo.

Este módulo define exceções específicas da aplicação que fornecem
mensagens de erro significativas e códigos de status HTTP apropriados.
"""

from fastapi import HTTPException, status
from typing import Any, Dict, Optional


class ALPException(HTTPException):
    """
    Exceção base para todas as exceções da aplicação RGA.
    Estende HTTPException do FastAPI para fornecer contexto adicional.
    """

    def __init__(
            self,
            status_code: int,
            detail: Any = None,
            headers: Optional[Dict[str, Any]] = None,
            internal_code: Optional[str] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.internal_code = internal_code


class ResourceNotFoundException(ALPException):
    """Recurso não encontrado."""

    def __init__(self, detail: str = "Recurso não encontrado", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{detail}{resource_info}",
            internal_code="RESOURCE_NOT_FOUND"
        )


class ResourceAlreadyExistsException(ALPException):
    """Recurso já existe."""

    def __init__(self, detail: str = "Recurso já existe", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{detail}{resource_info}",
            internal_code="RESOURCE_ALREADY_EXISTS"
        )


class PermissionDeniedException(ALPException):
    """Permissão negada."""

    def __init__(self, detail: str = "Permissão negada", permission: Optional[str] = None):
        permission_info = f" (Permissão necessária: {permission})" if permission else ""
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{detail}{permission_info}",
            internal_code="PERMISSION_DENIED"
        )


class InvalidCredentialsException(ALPException):
    """Credenciais inválidas."""

    def __init__(self, detail: str = "Credenciais inválidas"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            internal_code="INVALID_CREDENTIALS"
        )


class DatabaseOperationException(ALPException):
    """Erro na operação de banco de dados."""

    def __init__(self, detail: str = "Erro ao executar operação no banco de dados",
                 original_error: Optional[Exception] = None):
        error_info = f": {str(original_error)}" if original_error else ""
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{detail}{error_info}",
            internal_code="DATABASE_OPERATION_ERROR"
        )


class InvalidInputException(ALPException):
    """Dados de entrada inválidos."""

    def __init__(self, detail: str = "Dados de entrada inválidos", fields: Optional[Dict[str, str]] = None):
        field_errors = ""
        if fields:
            field_errors = ": " + ", ".join([f"{field}: {error}" for field, error in fields.items()])

        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{detail}{field_errors}",
            internal_code="INVALID_INPUT"
        )


class CategoryException(ALPException):
    """Exceção base para erros relacionados a categorias."""

    def __init__(
            self,
            status_code: int,
            detail: Any = None,
            headers: Optional[Dict[str, Any]] = None,
            internal_code: Optional[str] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers, internal_code=internal_code)


class ResourceInactiveException(ALPException):
    """Recurso encontrado, mas está inativo."""

    def __init__(self, detail: str = "Recurso está inativo", resource_id: Any = None):
        resource_info = f" (ID: {resource_id})" if resource_id is not None else ""
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{detail}{resource_info}",
            internal_code="RESOURCE_INACTIVE"
        )
