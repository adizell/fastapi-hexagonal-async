# app/shared/middleware/csrf_middleware.py

"""
Middleware para proteção contra ataques CSRF (Cross-Site Request Forgery).

Este módulo implementa mecanismos para proteger a API contra
ataques CSRF, verificando cabeçalhos de origem e referenciador.
"""

import logging
from typing import List, Set, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings

# Configurar logger
logger = logging.getLogger(__name__)


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware que implementa proteção contra CSRF para APIs RESTful.

    Para APIs que usam JWT ou outros tokens de portador (Bearer), a proteção CSRF
    é implementada verificando a origem da solicitação e o referenciador.
    """

    def __init__(self, app, **options):
        super().__init__(app)

        # Obter configurações da instância settings
        base_url = getattr(settings, "BASE_URL", "http://localhost:8000")
        self.allowed_origins = set(getattr(settings, "ALLOWED_ORIGINS", [base_url]))

        # Sempre incluir localhost para desenvolvimento
        self.allowed_origins.update([
            "http://localhost:8000",
            "http://127.0.0.1:8000"
        ])

        # Rotas seguras (que exigem verificação CSRF)
        # Por padrão, considera todas as rotas de métodos não GET como seguras
        self.safe_methods = {"GET", "HEAD", "OPTIONS"}

        # Rotas que estão isentas da verificação CSRF
        # Por exemplo, rotas públicas de login/registro
        self.exempt_routes = set(getattr(settings, "CSRF_EXEMPT_ROUTES", [
            "/user/login",
            "/user/register",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]))

        # Para depuração
        logger.info(f"CSRF Middleware inicializado com origens permitidas: {self.allowed_origins}")
        logger.info(f"Rotas isentas de CSRF: {self.exempt_routes}")

    def _is_route_exempt(self, path: str) -> bool:
        """
        Verifica se uma rota está isenta da verificação CSRF.

        Args:
            path: Caminho da URL

        Returns:
            bool: True se a rota estiver isenta
        """
        # Verifica se a rota ou algum de seus prefixos está na lista de isenções
        for exempt_route in self.exempt_routes:
            if path == exempt_route or path.startswith(exempt_route + "/"):
                return True
        return False

    def _verify_csrf_protection(self, request: Request) -> Optional[JSONResponse]:
        """
        Verifica a proteção CSRF para uma requisição.

        Args:
            request: Objeto Request

        Returns:
            Optional[JSONResponse]: Resposta de erro se a verificação falhar, None se passar
        """
        # Obtém o caminho da requisição
        path = request.url.path

        # Se a rota estiver isenta ou o método for seguro, não aplica a verificação
        if self._is_route_exempt(path) or request.method in self.safe_methods:
            return None

        # Verifica o cabeçalho Origin
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")

        # Se não houver cabeçalho Origin nem Referer, e for uma requisição não-segura, bloqueia
        # Isso se aplica a requisições que não vêm de navegadores
        if not origin and not referer:
            # Em produção, bloqueia; em desenvolvimento, apenas avisa
            if settings.ENVIRONMENT == "production":
                logger.warning(f"CSRF Proteção: Requisição sem Origin/Referer para {path} rejeitada")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cabeçalhos de origem ausentes. Acesso negado."}
                )
            else:
                logger.warning(f"CSRF Proteção: Requisição sem Origin/Referer para {path} (permitido em dev)")
                return None

        # Se o Origin estiver presente, verifica se está na lista de permitidos
        if origin and origin not in self.allowed_origins:
            logger.warning(f"CSRF Proteção: Origin inválido: {origin} para {path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Origem não permitida. Acesso negado."}
            )

        # Se o Referer estiver presente mas não o Origin, verifica o Referer
        if not origin and referer:
            # Verifica se o referer começa com alguma das origens permitidas
            referer_valid = any(referer.startswith(allowed) for allowed in self.allowed_origins)
            if not referer_valid:
                logger.warning(f"CSRF Proteção: Referer inválido: {referer} para {path}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Referenciador não permitido. Acesso negado."}
                )

        # Verifica o cabeçalho X-Requested-With para requisições AJAX
        # A maioria das bibliotecas JavaScript modernas define este cabeçalho automaticamente
        requested_with = request.headers.get("X-Requested-With")
        if not requested_with and settings.ENVIRONMENT == "production":
            # Em produção, exigimos X-Requested-With para endpoints sensíveis
            # Isso pode ser personalizado para as necessidades específicas da aplicação
            sensitive_endpoints = {"/user/", "/pet/", "/specie/"}
            is_sensitive = any(path.startswith(endpoint) for endpoint in sensitive_endpoints)

            if is_sensitive:
                logger.warning(f"CSRF Proteção: X-Requested-With ausente para endpoint sensível: {path}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cabeçalho de solicitação AJAX ausente. Acesso negado."}
                )

        # Todas as verificações passaram
        return None

    async def dispatch(self, request: Request, call_next):
        """
        Processa a requisição com proteção CSRF.

        Args:
            request: Objeto Request
            call_next: Função para chamar o próximo middleware/endpoint

        Returns:
            Response: Resposta HTTP
        """
        # Adicione o log aqui
        logger.info(f"Verificação CSRF para: {request.method} {request.url.path}")

        # Verifica a proteção CSRF
        error_response = self._verify_csrf_protection(request)
        if error_response:
            return error_response

        # Se passou na verificação, continua para o próximo middleware/endpoint
        return await call_next(request)
