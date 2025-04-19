# app/shared/middleware/exception_middleware.py (async version)

"""
Middleware for centralized exception handling.

This module defines middleware that intercepts exceptions and formats
appropriate error responses for the client.
"""

import time
import logging
import traceback
from typing import Optional, Callable

from fastapi import Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from starlette.middleware.base import BaseHTTPMiddleware
from jose.exceptions import JWTError, ExpiredSignatureError

from app.domain.exceptions import DomainException
from app.adapters.configuration.config import settings

# Configure logger
logger = logging.getLogger(__name__)


class AsyncExceptionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for centralized exception handling.
    Captures specific exceptions and formats the response accordingly.
    """

    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.time()
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            return response

        except DomainException as exc:
            # Domain exceptions: mapping from pure exception to HTTP code based on 'internal_code'
            logger.warning(
                f"Domain exception: {str(exc)} | Code: {exc.internal_code} | "
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
            # Database integrity error
            error_info = str(exc)
            constraint_name = self._extract_constraint_name(error_info)

            if settings.ENVIRONMENT == "production":
                error_message = "Database integrity error"
                logger.error(
                    f"Integrity error: Type={type(exc).__name__} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = error_info
                logger.error(
                    f"Integrity error: {error_info} | "
                    f"Constraint={constraint_name or 'N/A'} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}"
                )

            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "detail": error_message,
                    "code": f"INTEGRITY_ERROR{f'_{constraint_name}' if constraint_name else ''}"
                }
            )

        except NoResultFound as exc:
            # Resource not found via ORM
            logger.warning(
                f"Resource not found: {str(exc)} | "
                f"Path: {request.url.path}"
            )
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "detail": "Resource not found",
                    "code": "RESOURCE_NOT_FOUND"
                }
            )

        except SQLAlchemyError as exc:
            # Other SQLAlchemy errors
            if settings.ENVIRONMENT == "production":
                error_message = "Internal database error"
                logger.error(
                    f"Database error: Type={type(exc).__name__} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = str(exc)
                logger.error(
                    f"Database error: {str(exc)} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}"
                )

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": error_message,
                    "code": "DATABASE_ERROR"
                }
            )

        except (JWTError, ExpiredSignatureError) as exc:
            # JWT authentication errors
            error_type = "Expired token" if isinstance(exc, ExpiredSignatureError) else "Invalid token"
            logger.warning(
                f"Authentication error: {error_type} | "
                f"Type={type(exc).__name__} | "
                f"Path: {request.url.path} | "
                f"Client: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": f"{error_type}. Please login again.",
                    "code": "INVALID_TOKEN"
                }
            )

        except PermissionError as exc:
            # Permission error (native Python)
            logger.warning(
                f"Permission error: {str(exc)} | "
                f"Path: {request.url.path} | "
                f"Client: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": "You don't have permission to access this resource.",
                    "code": "PERMISSION_DENIED"
                }
            )

        except ValueError as exc:
            # Validation error
            logger.warning(
                f"Validation error: {str(exc)} | "
                f"Path: {request.url.path} | "
                f"Client: {request.client.host if request.client else 'N/A'}"
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": str(exc),
                    "code": "VALIDATION_ERROR"
                }
            )

        except Exception as exc:
            # Unhandled exceptions
            if settings.ENVIRONMENT == "production":
                error_message = "Internal server error"
                logger.exception(
                    f"Unhandled exception: Type={type(exc).__name__} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}"
                )
            else:
                error_message = str(exc)
                stack_trace = traceback.format_exc()
                logger.exception(
                    f"Unhandled exception: {str(exc)} | "
                    f"Path: {request.url.path} | "
                    f"Client: {request.client.host if request.client else 'N/A'}\n"
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
        Attempts to extract the constraint name from an integrity error message.

        Args:
            error_message: The complete error message

        Returns:
            The constraint name or None if not found
        """
        import re

        # Common patterns for different databases
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
