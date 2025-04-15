# app/shared/middleware/logging_middleware.py

"""
Middleware para logging de requisições HTTP.

Este módulo implementa um middleware que registra informações
sobre requisições recebidas e respostas enviadas.
"""

import time
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.adapters.configuration.config import settings

# Configurar logger
logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware para logging de requisições.
    Registra informações sobre cada requisição recebida.
    """

    async def dispatch(self, request: Request, call_next):
        # Log da requisição - com informações limitadas em produção
        if settings.ENVIRONMENT == "production":
            logger.info(f"Requisição: {request.method} {request.url.path}")
        else:
            # Em desenvolvimento, pode incluir mais detalhes como query params
            query_params = dict(request.query_params)
            logger.info(
                f"Requisição: {request.method} {request.url.path} | "
                f"Query: {query_params if query_params else 'N/A'} | "
                f"Cliente: {request.client.host if request.client else 'N/A'}"
            )

        # Processa a requisição
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time

        # Log da resposta
        if settings.ENVIRONMENT == "production":
            logger.info(f"Resposta: {response.status_code} para {request.method} {request.url.path}")
        else:
            logger.info(
                f"Resposta: {response.status_code} para {request.method} {request.url.path} | "
                f"Tempo: {process_time:.4f}s"
            )

        return response
