# app/shared/middleware/security_headers_middleware.py

"""
Middleware para adicionar cabeçalhos de segurança HTTP.

Este módulo implementa um middleware que adiciona cabeçalhos de segurança
às respostas HTTP para proteger contra vulnerabilidades web comuns.
"""

import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.adapters.configuration.config import settings

# Configurar logger
logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware que adiciona cabeçalhos de segurança a todas as respostas HTTP.

    Os cabeçalhos incluídos ajudam a proteger contra:
    - Cross-site scripting (XSS)
    - Clickjacking
    - MIME-type sniffing
    - Vazamento de informações
    - Transport Layer Security (forçar HTTPS)
    """

    async def dispatch(self, request: Request, call_next):
        # Processa a requisição
        response = await call_next(request)

        # Verifica se a rota é relacionada à documentação, templates do cliente, ou recursos estáticos
        path = request.url.path
        is_docs_route = path in ["/", "/docs", "/redoc", "/openapi.json"] or path.startswith(
            "/docs/") or path.startswith("/redoc/")
        is_client_template = path in ["/create-url/client", "/create-jwt/client", "/update-url/client"]
        is_static_resource = path.startswith(("/static/", "/css/", "/js/", "/favicon.ico"))

        # Não aplicar políticas CSP restritivas para rotas de documentação ou templates de cliente
        if not (is_docs_route or is_client_template or is_static_resource):
            # Ajuda a prevenir ataques XSS
            response.headers["X-XSS-Protection"] = "1; mode=block"

            # Previne MIME-type sniffing
            response.headers["X-Content-Type-Options"] = "nosniff"

            # Controla em que contexto o site pode ser incorporado (previne clickjacking)
            response.headers["X-Frame-Options"] = "SAMEORIGIN"

            # CSP restritivo para rotas da API
            csp_value = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-src 'none'; "
                "object-src 'none'; "
                "base-uri 'self'"
            )
            response.headers["Content-Security-Policy"] = csp_value

            # Controle de referência - limita informações enviadas a outros sites
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # Feature-Policy/Permissions-Policy - controle rígido sobre funcionalidades do navegador
            permissions_policy = (
                "accelerometer=(), "
                "camera=(), "
                "geolocation=(), "
                "gyroscope=(), "
                "magnetometer=(), "
                "microphone=(), "
                "payment=(), "
                "usb=()"
            )
            response.headers["Permissions-Policy"] = permissions_policy
            response.headers["Feature-Policy"] = permissions_policy

            # Cache-Control para rotas da API
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Cabeçalhos seguros para todas as rotas, incluindo documentação

        # Não expor informações sensíveis no cabeçalho Server
        if "Server" in response.headers:
            response.headers["Server"] = "RGA API"

        # Só habilita HSTS se a aplicação estiver configurada para usar HTTPS
        if settings.ENVIRONMENT == "production" and getattr(settings, "USE_HTTPS", False):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Configurações de cache para assets estáticos
        if path.startswith(("/static/", "/favicon.ico")):
            response.headers["Cache-Control"] = "public, max-age=3600"  # Cache por 1 hora

        return response
