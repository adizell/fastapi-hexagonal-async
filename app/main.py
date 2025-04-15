# app/main.py

"""
Módulo principal da aplicação RGA API.

Este módulo configura a aplicação FastAPI, seus middlewares, rotas, documentação,
e outros aspectos necessários para o funcionamento da API.
"""

import os
import logging
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from app.adapters.inbound.api.v1.router import api_router as api_v1_router
from app.adapters.inbound.api.v1.endpoints import client_auth

from app.shared.middleware import (
    ExceptionMiddleware,
    RequestLoggingMiddleware,
    CSRFProtectionMiddleware,
    RateLimitingMiddleware,
    SecurityHeadersMiddleware
)

# Configuração de logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Criar a instância do FastAPI
app = FastAPI(
    title="ADIZELL",
    description="FastAPI Hexagonal Async",
    version="1.0.0"
)

# Estabelecer o caminho absoluto para os arquivos estáticos
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Criar diretórios se não existirem
os.makedirs(os.path.join(static_dir, "img"), exist_ok=True)

# Montar o diretório de arquivos estáticos
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Adicionar middlewares - na ordem correta
app.add_middleware(SecurityHeadersMiddleware)  # Primeiro: adiciona cabeçalhos de segurança
app.add_middleware(CSRFProtectionMiddleware)  # Segundo: proteção CSRF
app.add_middleware(RequestLoggingMiddleware)  # Terceiro: logging
app.add_middleware(RateLimitingMiddleware)  # Quarto: rate limiting
app.add_middleware(ExceptionMiddleware)  # Quinto: tratamento de exceções

app.include_router(client_auth.jwt_router)
app.include_router(client_auth.create_url_router)
app.include_router(client_auth.update_url_router)


# Rota específica para o favicon na raiz
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/img/favicon.ico")


# Rota para redirecionamento para documentação Redoc
@app.get("/redoc", include_in_schema=False)
async def redoc():
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title="Documentação da API",
    )


# Rota raiz que redireciona para a documentação Swagger
@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return get_swagger_ui_html(openapi_url=app.openapi_url, title=app.title)


# Incluir o router v1 - ÚNICO PONTO DE INCLUSÃO DE ROTAS
app.include_router(api_v1_router, prefix="/api/v1")


# Personalização do schema OpenAPI
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Removendo os dtos indesejados da documentação
    if "components" in openapi_schema and "dtos" in openapi_schema["components"]:
        schemas_to_remove = ["HTTPValidationError", "ValidationError"]
        for schema in schemas_to_remove:
            openapi_schema["components"]["dtos"].pop(schema, None)

    # # Identificar tags duplicadas e consolidá-las
    # if "tags" in openapi_schema:
    #     unique_tags = {}
    #     for tag in openapi_schema.get("tags", []):
    #         tag_name = tag.get("name")
    #         if tag_name and tag_name not in unique_tags:
    #             unique_tags[tag_name] = tag
    #     openapi_schema["tags"] = list(unique_tags.values())

    # Remover o response 422 que referencia os dtos removidos
    for path_item in openapi_schema.get("paths", {}).values():
        for operation in path_item.values():
            if "responses" in operation and "422" in operation["responses"]:
                # Removendo completamente o response 422
                del operation["responses"]["422"]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
