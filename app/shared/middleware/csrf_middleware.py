# app/shared/middleware/csrf_middleware.py (async version)

"""
Middleware for CSRF (Cross-Site Request Forgery) protection.

This module implements mechanisms to protect the API against
CSRF attacks by verifying origin and referer headers.
"""

import logging
from typing import Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.adapters.configuration.config import settings

# Configure logger
logger = logging.getLogger(__name__)


class AsyncCSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that implements CSRF protection for RESTful APIs.

    For APIs using JWT or other bearer tokens, CSRF protection
    is implemented by verifying the request origin and referer.
    """

    def __init__(self, app, **options):
        super().__init__(app)

        # Get settings from the settings instance
        base_url = getattr(settings, "BASE_URL", "http://localhost:8000")
        self.allowed_origins = set(getattr(settings, "ALLOWED_ORIGINS", [base_url]))

        # Always include localhost for development
        self.allowed_origins.update([
            "http://localhost:8000",
            "http://127.0.0.1:8000"
        ])

        # Safe routes (that require CSRF verification)
        # By default, consider all non-GET methods as unsafe
        self.safe_methods = {"GET", "HEAD", "OPTIONS"}

        # Routes that are exempt from CSRF verification
        # For example, public login/register routes
        self.exempt_routes = set(getattr(settings, "CSRF_EXEMPT_ROUTES", [
            "/user/login",
            "/user/register",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]))

        # For debugging
        logger.info(f"CSRF Middleware initialized with allowed origins: {self.allowed_origins}")
        logger.info(f"CSRF exempt routes: {self.exempt_routes}")

    def _is_route_exempt(self, path: str) -> bool:
        """
        Check if a route is exempt from CSRF verification.

        Args:
            path: URL path

        Returns:
            bool: True if the route is exempt
        """
        # Check if the route or any of its prefixes is in the exemption list
        for exempt_route in self.exempt_routes:
            if path == exempt_route or path.startswith(exempt_route + "/"):
                return True
        return False

    def _verify_csrf_protection(self, request: Request) -> Optional[JSONResponse]:
        """
        Verify CSRF protection for a request.

        Args:
            request: Request object

        Returns:
            Optional[JSONResponse]: Error response if verification fails, None if it passes
        """
        # Get the request path
        path = request.url.path

        # If the route is exempt or the method is safe, don't apply verification
        if self._is_route_exempt(path) or request.method in self.safe_methods:
            return None

        # Check the Origin header
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")

        # If there's no Origin or Referer header, and it's an unsafe request, block it
        # This applies to requests that don't come from browsers
        if not origin and not referer:
            # In production, block; in development, just warn
            if settings.ENVIRONMENT == "production":
                logger.warning(f"CSRF Protection: Request without Origin/Referer for {path} rejected")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Missing origin headers. Access denied."}
                )
            else:
                logger.warning(f"CSRF Protection: Request without Origin/Referer for {path} (allowed in dev)")
                return None

        # If Origin is present, check if it's in the allowed list
        if origin and origin not in self.allowed_origins:
            logger.warning(f"CSRF Protection: Invalid Origin: {origin} for {path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Origin not allowed. Access denied."}
            )

        # If Referer is present but not Origin, check the Referer
        if not origin and referer:
            # Check if referer starts with any of the allowed origins
            referer_valid = any(referer.startswith(allowed) for allowed in self.allowed_origins)
            if not referer_valid:
                logger.warning(f"CSRF Protection: Invalid Referer: {referer} for {path}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Referer not allowed. Access denied."}
                )

        # Check the X-Requested-With header for AJAX requests
        # Most modern JavaScript libraries set this header automatically
        requested_with = request.headers.get("X-Requested-With")
        if not requested_with and settings.ENVIRONMENT == "production":
            # In production, require X-Requested-With for sensitive endpoints
            # This can be customized for the specific needs of the application
            sensitive_endpoints = {"/user/", "/pet/", "/specie/"}
            is_sensitive = any(path.startswith(endpoint) for endpoint in sensitive_endpoints)

            if is_sensitive:
                logger.warning(f"CSRF Protection: X-Requested-With missing for sensitive endpoint: {path}")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Missing AJAX request header. Access denied."}
                )

        # All checks passed
        return None

    async def dispatch(self, request: Request, call_next):
        """
        Process the request with CSRF protection.

        Args:
            request: Request object
            call_next: Function to call the next middleware/endpoint

        Returns:
            Response: HTTP response
        """
        # Log statement for debugging
        logger.info(f"CSRF check for: {request.method} {request.url.path}")

        # Verify CSRF protection
        error_response = self._verify_csrf_protection(request)
        if error_response:
            return error_response

        # If passed verification, continue to the next middleware/endpoint
        return await call_next(request)
