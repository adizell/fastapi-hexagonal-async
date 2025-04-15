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

from app.domain.exceptions import ALPException
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

        except ALPException as exc:
            # Exceções da aplicação - já formatadas corretamente
            logger.warning(
                f"Exceção da aplicação: {exc.detail} | Código: {exc.internal_code} | "
                f"Status: {exc.status_code} | Path: {request.url.path}"
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "detail": exc.detail,
                    "code": exc.internal_code
                },
                headers=exc.headers
            )

        except IntegrityError as exc:
            # Exceções de integridade do banco de dados - geralmente violações de restrições

            # Extrair informações detalhadas para logging
            error_info = str(exc)
            constraint_name = self._extract_constraint_name(error_info)

            # Log detalhado com informações de constraint para debugging
            if settings.ENVIRONMENT == "production":
                # Log mais seguro para produção
                error_message = "Erro de integridade no banco de dados"
                logger.error(
                    f"Erro de integridade: Tipo={type(exc).__name__} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )
            else:
                # Log detalhado para ambientes não-produção
                error_message = str(exc)
                logger.error(
                    f"Erro de integridade: {error_info} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )

            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,  # Mais apropriado para erros de integridade
                content={
                    "detail": error_message,
                    "code": f"INTEGRITY_ERROR{f'_{constraint_name}' if constraint_name else ''}"
                }
            )

        except NoResultFound as exc:
            # Exceção específica para quando um recurso não é encontrado via ORM
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
            # Exceções de banco de dados
            # Em produção, não expor os detalhes completos do erro
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
            # Exceções relacionadas a autenticação JWT
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
            # Exceções de permissão (do Python)
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
            # Exceções de validação
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
            # Em produção, não expor os detalhes completos do erro
            if settings.ENVIRONMENT == "production":
                error_message = "Erro interno do servidor"
                logger.exception(
                    f"Exceção não tratada: Tipo={type(exc).__name__} | "
                    f"Path: {request.url.path} | "
                    f"Cliente: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = str(exc)
                # Em desenvolvimento, logar o traceback completo para debugging
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
            r'constraint "(.*?)"',  # PostgreSQL pattern
            r'CONSTRAINT (.*?) FOREIGN KEY',  # MySQL pattern
            r'CONSTRAINT `(.*?)`',  # MySQL pattern (backticks)
            r'UNIQUE constraint failed: (.*)',  # SQLite pattern
            r'violates unique constraint "(.*?)"',  # Another PostgreSQL pattern
            r'duplicate key value violates unique constraint "(.*?)"'  # Yet another PostgreSQL pattern
        ]

        for pattern in patterns:
            match = re.search(pattern, error_message)
            if match:
                return match.group(1)

        return None
