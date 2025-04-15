# app/shared/middleware/exception_middleware.py

"""
Middleware para tratamento centralizado de exceções.

Este módulo define um middleware que intercepta exceções e formata
respostas de erro adequadas para o cliente.
"""

import time
import logging
import traceback
from typing import Optional

from fastapi import Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from starlette.middleware.base import BaseHTTPMiddleware
from jose.exceptions import JWTError, ExpiredSignatureError

from app.domain.exceptions import DomainException
from app.adapters.configuration.config import settings

# Configurar logger
logger = logging.getLogger(__name__)


class ExceptionMiddleware(BaseHTTPMiddleware):
    """
    Middleware para tratamento centralizado de exceções.
    Captura exceções específicas e formata a resposta de acordo.
    """

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            return response

        except DomainException as exc:
            # Exceções do domínio: mapeamento da exceção pura para código HTTP baseado em 'internal_code'
            logger.warning(
                f"Exceção do domínio: {str(exc)} | Código: {exc.internal_code} | "
                f"Path: {request.url.path}"
            )
            if exc.internal_code == "RESOURCE_NOT_FOUND":
                status_code = status.HTTP_404_NOT_FOUND
            elif exc.internal_code == "RESOURCE_ALREADY_EXISTS":
                status_code = status.HTTP_409_CONFLICT
            elif exc.internal_code == "PERMISSION_DENIED":
                status_code = status.HTTP_403_FORBIDDEN
            elif exc.internal_code == "INVALID_CREDENTIALS":
                status_code = status.HTTP_401_UNAUTHORIZED
            elif exc.internal_code == "DATABASE_OPERATION_ERROR":
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            elif exc.internal_code == "INVALID_INPUT":
                status_code = status.HTTP_400_BAD_REQUEST
            elif exc.internal_code == "RESOURCE_INACTIVE":
                status_code = status.HTTP_400_BAD_REQUEST
            else:
                status_code = status.HTTP_400_BAD_REQUEST

            return JSONResponse(
                status_code=status_code,
                content={
                    "detail": str(exc),
                    "code": exc.internal_code,
                    "errors": getattr(exc, "details", {})
                }
            )

        except IntegrityError as exc:
            # Erro de integridade do banco de dados
            error_info = str(exc)
            constraint_name = self._extract_constraint_name(error_info)

            if settings.ENVIRONMENT == "production":
                error_message = "Erro de integridade no banco de dados"
                logger.error(
                    f"Erro de integridade: Tipo={type(exc).__name__} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = error_info
                logger.error(
                    f"Erro de integridade: {error_info} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )

            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "detail": error_message,
                    "code": f"INTEGRITY_ERROR{f'_{constraint_name}' if constraint_name else ''}"
                }
            )

        except NoResultFound as exc:
            # Recurso não encontrado via ORM
            logger.warning(
                f"Recurso não encontrado: {str(exc)} | "
                f"Path: {request.url.path}"
            )
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "detail": "Recurso não encontrado",
                    "code": "RESOURCE_NOT_FOUND"
                }
            )

        except SQLAlchemyError as exc:
            # Outros erros do SQLAlchemy
            if settings.ENVIRONMENT == "production":
                error_message = "Erro interno de banco de dados"
                logger.error(
                    f"Erro de banco de dados: Tipo={type(exc).__name__} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = str(exc)
                logger.error(
                    f"Erro de banco de dados: {str(exc)} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": error_message,
                    "code": "DATABASE_ERROR"
                }
            )

        except (JWTError, ExpiredSignatureError) as exc:
            # Erros relacionados a autenticação JWT
            error_type = "Token expirado" if isinstance(exc, ExpiredSignatureError) else "Token inválido"
            logger.warning(
                f"Erro de autenticação: {error_type} | "
                f"Tipo={type(exc).__name__} | "
                f"Path: {request.url.path} | "
                f"Cliente: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": f"{error_type}. Por favor, faça login novamente.",
                    "code": "INVALID_TOKEN"
                }
            )

        except PermissionError as exc:
            # Erro de permissão (nativo do Python)
            logger.warning(
                f"Erro de permissão: {str(exc)} | "
                f"Path: {request.url.path} | "
                f"Cliente: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": "Você não tem permissão para acessar este recurso.",
                    "code": "PERMISSION_DENIED"
                }
            )

        except ValueError as exc:
            # Erro de validação
            logger.warning(
                f"Erro de validação: {str(exc)} | "
                f"Path: {request.url.path} | "
                f"Cliente: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": str(exc),
                    "code": "VALIDATION_ERROR"
                }
            )

        except Exception as exc:
            # Exceções não tratadas
            if settings.ENVIRONMENT == "production":
                error_message = "Erro interno do servidor"
                logger.exception(
                    f"Exceção não tratada: Tipo={type(exc).__name__} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = str(exc)
                stack_trace = traceback.format_exc()
                logger.exception(
                    f"Exceção não tratada: {str(exc)} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}\n"
                    f"Traceback: {stack_trace}"
                )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": error_message,
                    "code": "INTERNAL_SERVER_ERROR"
                }
            )

    def _extract_constraint_name(self, error_message: str) -> Optional[str]:
        """
        Tenta extrair o nome da constraint de uma mensagem de erro de integridade.

        Args:
            error_message: A mensagem de erro completa

        Returns:
            O nome da constraint ou None se não encontrado
        """
        import re

        # Padrões comuns para diferentes bancos de dados
        patterns = [
            r'constraint "(.*?)"',
            r'CONSTRAINT (.*?) FOREIGN KEY',
            r'CONSTRAINT `(.*?)`',
            r'UNIQUE constraint failed: (.*)',
            r'violates unique constraint "(.*?)"',
            r'duplicate key value violates unique constraint "(.*?)"'
        ]

        for pattern in patterns:
            match = re.search(pattern, error_message)
            if match:
                return match.group(1)
        return None
