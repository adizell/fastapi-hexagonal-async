# app/shared/middleware/rate_limiting_middleware.py (async version)

"""
Middleware for request rate limiting.

This module implements protection against excessive requests from the same client,
helping to prevent brute force attacks and DoS.
"""

import time
from datetime import datetime
import logging
from typing import Dict, Tuple, List, Set, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logger
logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """
    Robust in-memory rate limiting implementation.
    Limits requests by IP with different limits for default and sensitive routes.
    """

    def __init__(self):
        # Structure: {ip: [(timestamp1, path1), (timestamp2, path2), ...]}
        self.requests: Dict[str, List[Tuple[float, str]]] = {}

        # Time period in seconds for limits (60-second window)
        self.window_time = 60

        # Default request limit per minute per IP
        self.default_limit = 100

        # Limit for sensitive routes like login, registration, etc.
        self.sensitive_limit = 10

        # Set of routes considered sensitive
        self.sensitive_routes: Set[str] = {
            "/user/login",
            "/user/register",
            "/create-jwt/client",
            "/create-url/client",
            "/update-url/client"
        }

        # Cache of temporarily blocked IPs (with expiration time)
        # Structure: {ip: release_timestamp}
        self.blocked_ips: Dict[str, float] = {}

        # Block duration in seconds (5 minutes)
        self.block_duration = 300

        # Cache to store authentication failures by IP
        # Structure: {ip: [(timestamp1, path1), ...]}
        self.auth_failures: Dict[str, List[Tuple[float, str]]] = {}

        # Authentication failure limit before increasing the block
        self.auth_failure_limit = 5

        # Block duration for authentication failure (10 minutes)
        self.auth_block_duration = 600

    def _clean_old_requests(self, ip: str):
        """Remove old requests outside the time window."""
        if ip not in self.requests:
            return

        current_time = time.time()
        cutoff_time = current_time - self.window_time

        # Keep only requests within the time window
        self.requests[ip] = [
            (timestamp, path) for timestamp, path in self.requests[ip]
            if timestamp > cutoff_time
        ]

        # Remove the IP from the dictionary if no more requests
        if not self.requests[ip]:
            del self.requests[ip]

    def _clean_old_auth_failures(self, ip: str):
        """Remove old authentication failures outside the time window."""
        if ip not in self.auth_failures:
            return

        current_time = time.time()
        cutoff_time = current_time - (self.window_time * 5)  # 5-minute window for auth failures

        # Keep only failures within the time window
        self.auth_failures[ip] = [
            (timestamp, path) for timestamp, path in self.auth_failures[ip]
            if timestamp > cutoff_time
        ]

        # Remove the IP from the dictionary if no more failures
        if not self.auth_failures[ip]:
            del self.auth_failures[ip]

    def _clean_expired_blocks(self):
        """Remove IPs whose block has expired."""
        current_time = time.time()
        expired_ips = [ip for ip, block_until in self.blocked_ips.items()
                       if block_until <= current_time]

        for ip in expired_ips:
            del self.blocked_ips[ip]

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is temporarily blocked."""
        self._clean_expired_blocks()
        return ip in self.blocked_ips

    async def add_auth_failure(self, ip: str, path: str):
        """
        Register an authentication failure for an IP.

        Args:
            ip: Client IP address
            path: Request path
        """
        if ip not in self.auth_failures:
            self.auth_failures[ip] = []

        current_time = time.time()
        self.auth_failures[ip].append((current_time, path))

        # Clean old failures
        self._clean_old_auth_failures(ip)

        # Check if exceeded the failure limit
        if len(self.auth_failures[ip]) >= self.auth_failure_limit:
            await self.block_ip(ip, is_auth_failure=True)

    async def block_ip(self, ip: str, is_auth_failure: bool = False):
        """
        Temporarily block an IP.

        Args:
            ip: Client IP address
            is_auth_failure: If the block is due to authentication failures
        """
        duration = self.auth_block_duration if is_auth_failure else self.block_duration
        block_until = time.time() + duration
        self.blocked_ips[ip] = block_until

        block_type = "authentication failures" if is_auth_failure else "excessive requests"
        logger.warning(
            f"IP {ip} blocked due to {block_type} until {datetime.fromtimestamp(block_until).strftime('%Y-%m-%d %H:%M:%S')}"
        )

    async def is_rate_limited(self, ip: str, path: str) -> Tuple[bool, Optional[int]]:
        """
        Check if an IP has exceeded the request limit.

        Args:
            ip: Client IP address
            path: Request path

        Returns:
            Tuple (is_limited, remaining_requests)
            - is_limited: True if the IP exceeded the limit
            - remaining_requests: Number of remaining requests or None if limited
        """
        # Check if already blocked
        if self.is_blocked(ip):
            return True, None

        # Clean old requests
        self._clean_old_requests(ip)

        # Initialize requests list if first access
        if ip not in self.requests:
            self.requests[ip] = []

        # Determine if it's a sensitive route
        is_sensitive = any(path.startswith(route) for route in self.sensitive_routes)
        limit = self.sensitive_limit if is_sensitive else self.default_limit

        # Count the number of requests for this type of route
        if is_sensitive:
            count = sum(1 for _, req_path in self.requests[ip]
                        if any(req_path.startswith(route) for route in self.sensitive_routes))
        else:
            count = len(self.requests[ip])

        # Check if exceeded the limit
        if count >= limit:
            # If a sensitive route and exceeded limit by a lot, block the IP
            if is_sensitive and count >= limit * 2:
                await self.block_ip(ip)
            return True, 0

        # Add the current request
        current_time = time.time()
        self.requests[ip].append((current_time, path))

        # Return how many requests still remain
        remaining = limit - count - 1
        return False, remaining


# Global rate limiter instance
async_rate_limiter = AsyncRateLimiter()


class AsyncRateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that limits the number of requests by IP.
    """

    async def dispatch(self, request: Request, call_next):
        # Get the client IP
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Ignore documentation and static routes
        if path in ["/", "/docs", "/redoc", "/openapi.json"] or path.startswith("/static/"):
            return await call_next(request)

        # Check rate limiting
        is_limited, remaining = await async_rate_limiter.is_rate_limited(client_ip, path)

        if is_limited:
            logger.warning(f"Rate limit exceeded for IP: {client_ip} on path: {path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Too many requests. Try again later.",
                    "code": "RATE_LIMIT_EXCEEDED"
                },
                headers={"Retry-After": "60"}  # Suggest trying again after 60 seconds
            )

        # Process the request
        response = await call_next(request)

        # Add informative rate limiting headers
        if remaining is not None:
            response.headers["X-RateLimit-Remaining"] = str(remaining)

        # Capture authentication failures (401) for sensitive routes
        if (response.status_code == 401 and
                any(path.startswith(route) for route in async_rate_limiter.sensitive_routes)):
            await async_rate_limiter.add_auth_failure(client_ip, path)

        return response
