# app/adapters/inbound/api/deps.py

"""
Dependências para injeção nos endpoints da API.

Este módulo define as funções que fornecem dependências via
FastAPI Depends() para autenticação, autorização e acesso ao banco de dados.
"""

import logging
from uuid import UUID
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.adapters.outbound.persistence.database import get_db
from app.adapters.outbound.persistence.models.user_model import User
from app.adapters.outbound.persistence.models.client_model import Client
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager

# Configurar logger
logger = logging.getLogger(__name__)

# Criar scheme de bearer token para autenticação
bearer_scheme = HTTPBearer()

########################################################################
# Gerenciamento de Sessão de Banco de Dados
########################################################################

# Alias de get_db para retrocompatibilidade
get_session = get_db
get_db_session = get_db


########################################################################
# Autenticação via Token do Client
########################################################################

def verify_client_token(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> str:
    """
    Verifica e decodifica um token JWT de client.

    Args:
        credentials: Credenciais de autorização com bearer token

    Returns:
        ID do client (sub) contido no token

    Raises:
        HTTPException: Se o token for inválido ou expirado
    """
    token = credentials.credentials
    payload = ClientAuthManager.verify_client_token(token)
    sub = payload.get("sub")
    if not sub:
        logger.warning(f"Token inválido: 'sub' não encontrado em token de client")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido: 'sub' não encontrado no token do client.",
        )
    return sub


def get_current_client(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: Session = Depends(get_db),
) -> Client:
    """
    Obtém o client atual a partir do token.

    Args:
        credentials: Credenciais de autorização com bearer token
        db: Sessão do banco de dados

    Returns:
        Objeto Client autenticado

    Raises:
        HTTPException: Se o token for inválido ou o client não existir/estiver inativo
    """
    try:
        token = credentials.credentials
        payload = ClientAuthManager.verify_client_token(token)
        client_id = payload.get("sub")

        try:
            client_id = int(client_id)
        except (ValueError, TypeError):
            logger.warning(f"Token de client inválido: 'sub' não é um inteiro ({client_id})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token do client inválido: 'sub' não é um inteiro.",
            )

        client = db.query(Client).filter(Client.id == client_id, Client.is_active.is_(True)).first()
        if not client:
            logger.warning(f"Client ID {client_id} não encontrado ou inativo")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client não encontrado ou inativo.",
            )
        return client

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Erro não esperado ao autenticar client: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro de autenticação do client.",
        )


########################################################################
# Autenticação via Token do Usuário
########################################################################

def get_current_user(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: Session = Depends(get_db),
) -> User:
    """
    Obtém o usuário atual a partir do token.

    Args:
        credentials: Credenciais de autorização com bearer token
        db: Sessão do banco de dados

    Returns:
        Objeto User autenticado

    Raises:
        HTTPException: Se o token for inválido ou o usuário não existir/estiver inativo
    """
    try:
        token = credentials.credentials
        # Pass db to verify_access_token
        payload = UserAuthManager.verify_access_token(token, db=db)

        try:
            user_id = UUID(payload.get("sub"))
        except (ValueError, TypeError):
            logger.warning(f"Token inválido: 'sub' não é um UUID válido ({payload.get('sub')})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido: 'sub' não é um UUID válido.",
            )

        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
        if not user:
            logger.warning(f"Usuário {user_id} não encontrado ou inativo")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário não encontrado ou inativo.",
            )
        return user

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Erro não esperado ao autenticar usuário: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro de autenticação do usuário.",
        )
