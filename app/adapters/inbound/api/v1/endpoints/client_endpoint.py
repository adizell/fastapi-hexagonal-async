# app/adapters/inbound/api/v1/endpoints/client_endpoint.py

"""
Endpoints para autenticação e gerenciamento de clients.

Este módulo contém rotas para geração de JWT para clients, criação de clients
e atualização de credenciais de clients.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
import logging

from app.adapters.inbound.api.deps import get_db_session
from app.adapters.outbound.security.token_store import TokenStore
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager
from app.adapters.outbound.persistence.models.client_model import Client

# Configurar logging
logger = logging.getLogger(__name__)

# Criar router base para endpoints de JWT
jwt_router = APIRouter(tags=["Client JWT"], include_in_schema=False)

# Criar router para criação de client via URL
create_url_router = APIRouter(tags=["Client Creation"], include_in_schema=False)

# Criar router para atualização de client via URL
update_url_router = APIRouter(tags=["Client Update"], include_in_schema=False)

# Templates para as páginas HTML
templates = Jinja2Templates(directory="app/templates")


# Endpoints para geração de JWT
@jwt_router.get("/create-jwt/client", response_class=HTMLResponse)
async def client_login_form(request: Request):
    """
    Exibe o formulário HTML para o login do client (gera token).
    """
    return templates.TemplateResponse("create_client_jwt.html", {"request": request})


@jwt_router.post("/create-jwt/client", response_class=HTMLResponse)
async def client_login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        db_session: AsyncSession = Depends(get_db_session),
):
    """
    Verifica as credenciais do client e gera um token JWT.

    Args:
        request: Objeto de requisição FastAPI
        username: Client ID do cliente
        password: Senha do cliente
        db_session: Sessão do banco de dados

    Returns:
        HTMLResponse: Resposta com template renderizado
    """
    try:
        # Valida a senha contra os hashes armazenados
        if not TokenStore.validate(password, ClientAuthManager.crypt_context):
            logger.warning(f"Tentativa de login com senha inválida para client: {username}")
            return templates.TemplateResponse("create_client_jwt.html", {
                "request": request,
                "error": "Senha incorreta. Token não gerado."
            })

        # Busca o client no banco para obter o ID (sub no token)
        stmt = select(Client).where(Client.client_id == username)
        result = await db_session.execute(stmt)
        client = result.scalar_one_or_none()

        if not client:
            logger.warning(f"Tentativa de login com client inexistente: {username}")
            return templates.TemplateResponse("create_client_jwt.html", {
                "request": request,
                "error": "Client não encontrado. Por favor, verifique o Client ID."
            })

        # Verifica se o client está ativo
        if not client.is_active:
            logger.warning(f"Tentativa de login com client inativo: {username}")
            return templates.TemplateResponse("create_client_jwt.html", {
                "request": request,
                "error": "Este Client está inativo. Por favor, contate o administrador do sistema."
            })

        # Gera token com o ID do client (convertendo para string para garantir compatibilidade)
        token = await ClientAuthManager.create_client_token(subject=str(client.id))
        logger.info(f"Token JWT gerado com sucesso para client: {username}")

        return templates.TemplateResponse("create_client_jwt.html", {
            "request": request,
            "client_id": username,
            "success": True,
            "token": token
        })

    except SQLAlchemyError as e:
        logger.error(f"Erro de banco de dados ao autenticar client: {e}")
        return templates.TemplateResponse("create_client_jwt.html", {
            "request": request,
            "error": "Erro ao consultar banco de dados. Tente novamente."
        })
    except Exception as e:
        logger.error(f"Erro inesperado ao autenticar client: {e}")
        return templates.TemplateResponse("create_client_jwt.html", {
            "request": request,
            "error": "Erro interno do servidor. Tente novamente mais tarde."
        })


# Endpoints para criação de client via URL
@create_url_router.get("/create-url/client", response_class=HTMLResponse)
async def create_client_form(request: Request):
    """
    Exibe o formulário HTML para criar um novo client.
    """
    return templates.TemplateResponse("create_client_url.html", {"request": request})


@create_url_router.post("/create-url/client", response_class=HTMLResponse)
async def create_client(
        request: Request,
        password: str = Form(...),
        db_session: AsyncSession = Depends(get_db_session),
):
    """
    Cria um novo client após validar a senha administrativa.

    Args:
        request: Objeto de requisição FastAPI
        password: Senha administrativa para autorizar a criação
        db_session: Sessão do banco de dados

    Returns:
        HTMLResponse: Resposta com template renderizado
    """
    # Verifica se a senha é válida
    if not TokenStore.validate(password, ClientAuthManager.crypt_context):
        return templates.TemplateResponse("create_client_url.html", {
            "request": request,
            "error": "Senha incorreta. Acesso negado.",
        })

    try:
        from app.application.use_cases.client_use_cases import AsyncClientService
        uc = AsyncClientService(db_session)
        # Pass the password to create_client
        credentials = await uc.create_client(admin_password=password)

        return templates.TemplateResponse("create_client_url.html", {
            "request": request,
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "success": True
        })
    except Exception as e:
        return templates.TemplateResponse("create_client_url.html", {
            "request": request,
            "error": f"Erro ao criar client: {str(e)}",
        })


# Endpoints para atualização de client via URL
@update_url_router.get("/update-url/client", response_class=HTMLResponse)
async def update_client_form(request: Request):
    """
    Exibe o formulário HTML para atualizar a chave secreta do client.
    """
    return templates.TemplateResponse("update_client_url.html", {"request": request})


@update_url_router.post("/update-url/client", response_class=HTMLResponse)
async def update_client_secret(
        request: Request,
        client_id: str = Form(...),
        password: str = Form(...),
        db_session: AsyncSession = Depends(get_db_session),
):
    """
    Atualiza a chave secreta de um client após validação da senha administrativa.

    Args:
        request: Objeto de requisição FastAPI
        client_id: ID do client a ser atualizado
        password: Senha administrativa para autorizar a atualização
        db_session: Sessão do banco de dados

    Returns:
        HTMLResponse: Resposta com template renderizado
    """
    # Verifica se a senha é válida
    if not TokenStore.validate(password, ClientAuthManager.crypt_context):
        return templates.TemplateResponse("update_client_url.html", {
            "request": request,
            "error": "Senha incorreta. Atualização não permitida.",
        })

    try:
        # Busca o client para verificar se existe
        stmt = select(Client).where(Client.client_id == client_id)
        result = await db_session.execute(stmt)
        client = result.scalar_one_or_none()

        if not client:
            return templates.TemplateResponse("update_client_url.html", {
                "request": request,
                "error": "Client não encontrado. Por favor, verifique o Client ID.",
            })

        # Verifica se o client está ativo
        if not client.is_active:
            return templates.TemplateResponse("update_client_url.html", {
                "request": request,
                "error": "Este Client está inativo. Por favor, contate o administrador do sistema para reativá-lo.",
            })

        # Atualiza o secret do client
        from app.application.use_cases.client_use_cases import AsyncClientService
        uc = AsyncClientService(db_session)
        result = await uc.update_client_secret(client_id=client_id, admin_password=password)

        # Gerar token JWT com o ID do client
        token = await ClientAuthManager.create_client_token(subject=str(client.id))

        return templates.TemplateResponse("update_client_url.html", {
            "request": request,
            "client_id": client_id,
            "client_secret": result.get("new_client_secret"),
            "token": token,
            "success": True
        })

    except Exception as e:
        return templates.TemplateResponse("update_client_url.html", {
            "request": request,
            "error": f"Erro ao atualizar client: {str(e)}",
        })
