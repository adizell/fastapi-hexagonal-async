# app/main.py

import logging
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.openapi.utils import get_openapi

from app.adapters.configuration.config import settings

# ── CONFIGURAÇÃO ÚNICA DE LOGGING ──────────────────────────────────────────────
level = logging.DEBUG if settings.DEBUG else getattr(logging, settings.LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=level,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)
# ────────────────────────────────────────────────────────────────────────────────


# Create FastAPI instance
app = FastAPI(
    title="ADIZELL",
    description="FastAPI Hexagonal Async",
    version="1.0.0",
    debug=settings.DEBUG,
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Middlewares
from app.shared.middleware import (
    ExceptionMiddleware,
    RequestLoggingMiddleware,
    CSRFProtectionMiddleware,
    RateLimitingMiddleware,
    SecurityHeadersMiddleware
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFProtectionMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitingMiddleware)
app.add_middleware(ExceptionMiddleware)

# Routers
from app.adapters.inbound.api.v1.router import api_router as api_v1_router
from app.adapters.inbound.api.v1.endpoints import client_endpoint

app.include_router(client_endpoint.jwt_router)
app.include_router(client_endpoint.create_url_router)
app.include_router(client_endpoint.update_url_router)
app.include_router(api_v1_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return RedirectResponse(url="/docs")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/img/favicon.ico")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    spec = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Remove schemas e respostas 422 indesejadas
    for schema in ("HTTPValidationError", "ValidationError"):
        spec.get("components", {}).get("schemas", {}).pop(schema, None)

    for path in spec.get("paths", {}).values():
        for op in path.values():
            op.get("responses", {}).pop("422", None)

    app.openapi_schema = spec
    return spec


app.openapi = custom_openapi


@app.on_event("startup")
async def startup_event():
    logger.info("Application starting up...")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application shutting down...")
