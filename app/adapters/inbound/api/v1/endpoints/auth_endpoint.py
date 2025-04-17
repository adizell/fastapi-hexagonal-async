# app/adapters/inbound/api/v1/endpoints/auth_endpoint.py

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.application.use_cases.auth_use_cases import AuthService
from app.adapters.outbound.persistence.models.user_model import User
from app.adapters.inbound.api.deps import get_session, get_current_client
from app.domain.exceptions import (
    ResourceAlreadyExistsException,
    InvalidCredentialsException,
    ResourceInactiveException,
)
from app.application.dtos.user_dto import UserCreate, UserOutput, TokenData, RefreshTokenRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/register",
    response_model=UserOutput,
    status_code=status.HTTP_201_CREATED,
    summary="Register User - Cria um novo usuário",
    description=(
            "Cria um novo usuário com endereço de email. É necessário um token JWT "
            "de client para validar a origem da criação."
    ),
)
def register_user(
        user_input: UserCreate,
        db: Session = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        return AuthService(db).register_user(user_input)

    except ResourceAlreadyExistsException as e:
        # email já existe
        logger.warning(f"Registro duplicado: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.details
        )

    except HTTPException:
        # repassa quaisquer HTTPException geradas internamente
        raise

    except Exception as e:
        logger.exception(f"Erro não tratado no registro: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno no servidor."
        )


@router.post(
    "/login",
    response_model=TokenData,
    summary="Login User - Gera token de acesso",
    description=(
            "Autentica um usuário (email/senha) e retorna um token JWT. "
            "Tentativas de login com usuários inativos resultarão em erro. "
            "Requer token de client válido."
    ),
)
def login_user(
        user_input: UserCreate,
        db: Session = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        return AuthService(db).login_user(user_input)

    except InvalidCredentialsException as e:
        logger.warning(f"Credenciais inválidas: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.details,
            headers={"WWW-Authenticate": "Bearer"},
        )

    except ResourceInactiveException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Conta de usuário inativa. Contate o administrador.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.exception(f"Erro não tratado no login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno no servidor."
        )


@router.post(
    "/refresh",
    response_model=TokenData,
    summary="Refresh Token - Renova o token de acesso",
    description=(
            "Gera um novo token de acesso a partir de um refresh token válido. "
            "Requer token de client válido."
    ),
)
def refresh_token(
        refresh_data: RefreshTokenRequest,
        db: Session = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        return AuthService(db).refresh_token(refresh_data.refresh_token)

    except InvalidCredentialsException as e:
        logger.warning(f"Refresh inválido: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.details,
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.exception(f"Erro ao renovar token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno no servidor."
        )
