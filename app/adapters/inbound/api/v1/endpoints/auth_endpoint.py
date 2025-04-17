# app/adapters/inbound/api/v1/endpoints/auth_endpoint.py

import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.application.use_cases.auth_use_cases import AuthService
from app.adapters.outbound.persistence.models.user_model import User
from app.adapters.inbound.api.deps import get_session, get_current_client
from app.adapters.configuration.config import settings
from app.domain.exceptions import (
    ResourceAlreadyExistsException,
    InvalidCredentialsException,
    ResourceInactiveException,
)
from app.application.dtos.user_dto import UserCreate, UserOutput, TokenData, RefreshTokenRequest

logger = logging.getLogger(__name__)
router = APIRouter()

# esquema de bearer para extrair o token do header Authorization
bearer_scheme = HTTPBearer()


@router.post(
    "/register",
    response_model=UserOutput,
    status_code=status.HTTP_201_CREATED,
    summary="Register User - Cria um novo usuário",
    description="Cria um novo usuário com endereço de email. É necessário um token JWT de client.",
)
def register_user(
        user_input: UserCreate,
        db: Session = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        return AuthService(db).register_user(user_input)

    except ResourceAlreadyExistsException as e:
        # agora usamos e.detail ou str(e) para enviar a mensagem correta
        msg = getattr(e, "detail", None) or str(e)
        logger.warning(f"Registro duplicado: {msg}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=msg
        )

    except HTTPException:
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


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout - Revoke current access token",
    description="Invalidates the current access token by adding it to the blacklist.",
)
def logout_user(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: Session = Depends(get_session),
):
    token = credentials.credentials
    try:
        # decodifica para extrair o jti e o exp
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token does not support revocation.",
            )
        expires_at = datetime.fromtimestamp(payload["exp"])

        # adiciona à blacklist
        from app.adapters.outbound.persistence.repositories.token_repository import token_repository
        token_repository.add_to_blacklist(db, jti, expires_at)

        return {"detail": "Successfully logged out."}

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )
