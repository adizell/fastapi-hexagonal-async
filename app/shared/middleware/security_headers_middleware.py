# app/shared/middleware/security_headers_middleware.py (async version)

"""
Middleware for adding HTTP security headers.

This module implements a middleware that adds security headers
to HTTP responses to protect against common web vulnerabilities.
"""

import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.adapters.configuration.config import settings

# Configure logger
logger = logging.getLogger(__name__)


class AsyncSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all HTTP responses.

    The headers included help protect against:
    - Cross-site scripting (XSS)
    - Clickjacking
    - MIME-type sniffing
    - Information leakage
    - Transport Layer Security (forcing HTTPS)
    """

    async def dispatch(self, request: Request, call_next):
        # Process the request
        response = await call_next(request)

        # Check if the route is related to documentation, client templates, or static resources
        path = request.url.path
        is_docs_route = path in ["/", "/docs", "/redoc", "/openapi.json"] or path.startswith(
            "/docs/") or path.startswith("/redoc/")
        is_client_template = path in ["/create-url/client", "/create-jwt/client", "/update-url/client"]
        is_static_resource = path.startswith(("/static/", "/css/", "/js/", "/favicon.ico"))

        # Don't apply restrictive CSP policies for documentation or client templates
        if not (is_docs_route or is_client_template or is_static_resource):
            # Helps prevent XSS attacks
            response.headers["X-XSS-Protection"] = "1; mode=block"

            # Prevents MIME-type sniffing
            response.headers["X-Content-Type-Options"] = "nosniff"

            # Controls in which context the site can be embedded (prevents clickjacking)
            response.headers["X-Frame-Options"] = "SAMEORIGIN"

            # Restrictive CSP for API routes
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

            # Referrer control - limits information sent to other sites
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # Feature-Policy/Permissions-Policy - strict control over browser features
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

            # Cache-Control for API routes
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Secure headers for all routes, including documentation

        # Don't expose sensitive information in the Server header
        if "Server" in response.headers:
            response.headers["Server"] = "RGA API"

        # Only enable HSTS if the application is configured to use HTTPS
        if settings.ENVIRONMENT == "production" and getattr(settings, "USE_HTTPS", False):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Cache settings for static assets
        if path.startswith(("/static/", "/favicon.ico")):
            response.headers["Cache-Control"] = "public, max-age=3600"  # Cache for 1 hour

        return response
