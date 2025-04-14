# app/core/middleware/rate_limiting_middleware.py

"""
Middleware para limitação de taxa de requisições (rate limiting).

Este módulo implementa proteção contra excesso de requisições de um mesmo cliente,
ajudando a prevenir ataques de força bruta e DoS.
"""

import time
from datetime import datetime
import logging
from typing import Dict, Tuple, List, Set, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Configurar logger
logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Implementação robusta de rate limiting usando armazenamento em memória.
    Limita requisições por IP com diferentes limites para rotas padrão e rotas sensíveis.
    """

    def __init__(self):
        # Estrutura: {ip: [(timestamp1, path1), (timestamp2, path2), ...]}
        self.requests: Dict[str, List[Tuple[float, str]]] = {}

        # Período de tempo em segundos para limites (janela de 60 segundos)
        self.window_time = 60

        # Limite de requisições padrão por minuto por IP
        self.default_limit = 100

        # Limite para rotas sensíveis como login, registro, etc.
        self.sensitive_limit = 10

        # Conjunto de rotas consideradas sensíveis
        self.sensitive_routes: Set[str] = {
            "/user/login",
            "/user/register",
            "/create-jwt/client",
            "/create-url/client",
            "/update-url/client"
        }

        # Cache de IPs bloqueados temporariamente (com tempo de expiração)
        # Estrutura: {ip: timestamp_de_liberação}
        self.blocked_ips: Dict[str, float] = {}

        # Duração do bloqueio em segundos (5 minutos)
        self.block_duration = 300

        # Cache para armazenar falhas de autenticação por IP
        # Estrutura: {ip: [(timestamp1, path1), ...]}
        self.auth_failures: Dict[str, List[Tuple[float, str]]] = {}

        # Limite de falhas de autenticação antes de aumentar o bloqueio
        self.auth_failure_limit = 5

        # Duração do bloqueio por falha de autenticação (10 minutos)
        self.auth_block_duration = 600

    def _clean_old_requests(self, ip: str):
        """Remove requisições antigas fora da janela de tempo."""
        if ip not in self.requests:
            return

        current_time = time.time()
        cutoff_time = current_time - self.window_time

        # Mantém apenas as requisições dentro da janela de tempo
        self.requests[ip] = [
            (timestamp, path) for timestamp, path in self.requests[ip]
            if timestamp > cutoff_time
        ]

        # Remove o IP do dicionário se não tiver mais requisições
        if not self.requests[ip]:
            del self.requests[ip]

    def _clean_old_auth_failures(self, ip: str):
        """Remove falhas de autenticação antigas fora da janela de tempo."""
        if ip not in self.auth_failures:
            return

        current_time = time.time()
        cutoff_time = current_time - (self.window_time * 5)  # Janela de 5 minutos para falhas de autenticação

        # Mantém apenas as falhas dentro da janela de tempo
        self.auth_failures[ip] = [
            (timestamp, path) for timestamp, path in self.auth_failures[ip]
            if timestamp > cutoff_time
        ]

        # Remove o IP do dicionário se não tiver mais falhas
        if not self.auth_failures[ip]:
            del self.auth_failures[ip]

    def _clean_expired_blocks(self):
        """Remove IPs cujo bloqueio já expirou."""
        current_time = time.time()
        expired_ips = [ip for ip, block_until in self.blocked_ips.items()
                       if block_until <= current_time]

        for ip in expired_ips:
            del self.blocked_ips[ip]

    def is_blocked(self, ip: str) -> bool:
        """Verifica se um IP está bloqueado temporariamente."""
        self._clean_expired_blocks()
        return ip in self.blocked_ips

    def add_auth_failure(self, ip: str, path: str):
        """
        Registra uma falha de autenticação para um IP.

        Args:
            ip: O endereço IP do cliente
            path: O caminho da requisição
        """
        if ip not in self.auth_failures:
            self.auth_failures[ip] = []

        current_time = time.time()
        self.auth_failures[ip].append((current_time, path))

        # Limpa falhas antigas
        self._clean_old_auth_failures(ip)

        # Verifica se excedeu o limite de falhas
        if len(self.auth_failures[ip]) >= self.auth_failure_limit:
            self.block_ip(ip, is_auth_failure=True)

    def block_ip(self, ip: str, is_auth_failure: bool = False):
        """
        Bloqueia um IP temporariamente.

        Args:
            ip: O endereço IP do cliente
            is_auth_failure: Se o bloqueio é devido a falhas de autenticação
        """
        duration = self.auth_block_duration if is_auth_failure else self.block_duration
        block_until = time.time() + duration
        self.blocked_ips[ip] = block_until

        block_type = "falhas de autenticação" if is_auth_failure else "excesso de requisições"
        logger.warning(
            f"IP {ip} bloqueado por {block_type} até {datetime.fromtimestamp(block_until).strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def is_rate_limited(self, ip: str, path: str) -> Tuple[bool, Optional[int]]:
        """
        Verifica se um IP excedeu o limite de requisições.

        Args:
            ip: O endereço IP do cliente
            path: O caminho da requisição

        Returns:
            Tupla (está_limitado, requisições_restantes)
            - está_limitado: True se o IP excedeu o limite
            - requisições_restantes: Número de requisições restantes ou None se limitado
        """
        # Verifica se já está bloqueado
        if self.is_blocked(ip):
            return True, None

        # Limpa requisições antigas
        self._clean_old_requests(ip)

        # Inicializa lista de requisições se for o primeiro acesso
        if ip not in self.requests:
            self.requests[ip] = []

        # Determina se é uma rota sensível
        is_sensitive = any(path.startswith(route) for route in self.sensitive_routes)
        limit = self.sensitive_limit if is_sensitive else self.default_limit

        # Conta o número de requisições para este tipo de rota
        if is_sensitive:
            count = sum(1 for _, req_path in self.requests[ip]
                        if any(req_path.startswith(route) for route in self.sensitive_routes))
        else:
            count = len(self.requests[ip])

        # Verifica se excedeu o limite
        if count >= limit:
            # Se for uma rota sensível e excedeu muito o limite, bloqueia o IP
            if is_sensitive and count >= limit * 2:
                self.block_ip(ip)
            return True, 0

        # Adiciona a requisição atual
        current_time = time.time()
        self.requests[ip].append((current_time, path))

        # Retorna quantas requisições ainda restam
        remaining = limit - count - 1
        return False, remaining


# Instância global do limitador
rate_limiter = RateLimiter()


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware que limita o número de requisições por IP.
    """

    async def dispatch(self, request: Request, call_next):
        # Obtém o IP do cliente
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Ignora rotas de documentação e estáticas
        if path in ["/", "/docs", "/redoc", "/openapi.json"] or path.startswith("/static/"):
            return await call_next(request)

        # Verifica rate limiting
        is_limited, remaining = rate_limiter.is_rate_limited(client_ip, path)

        if is_limited:
            logger.warning(f"Rate limit excedido para IP: {client_ip} no path: {path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Muitas requisições. Tente novamente mais tarde.",
                    "code": "RATE_LIMIT_EXCEEDED"
                },
                headers={"Retry-After": "60"}  # Sugere tentar novamente após 60 segundos
            )

        # Processa a requisição
        response = await call_next(request)

        # Adiciona cabeçalhos informativos de rate limiting
        if remaining is not None:
            response.headers["X-RateLimit-Remaining"] = str(remaining)

        # Captura falhas de autenticação (401) para rotas sensíveis
        if (response.status_code == 401 and
                any(path.startswith(route) for route in rate_limiter.sensitive_routes)):
            rate_limiter.add_auth_failure(client_ip, path)

        return response
