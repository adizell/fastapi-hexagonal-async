# app/application/use_cases/auth_use_cases.py

"""
Serviço para autenticação de usuários.

Este módulo implementa o serviço para operações de autenticação de usuários,
incluindo registro, login e renovação de tokens.
"""

import logging
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from typing import Dict, Optional

from app.adapters.configuration.config import settings
from app.adapters.outbound.persistence.repositories.user_repository import user as user_repository
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.application.dtos.user_dto import UserCreate, TokenData, UserOutput
from app.application.ports.inbound import IUserUseCase
from app.domain.exceptions import InvalidCredentialsException, DatabaseOperationException, \
    ResourceAlreadyExistsException
from app.domain.services.auth_service import AuthService as DomainAuthService

logger = logging.getLogger(__name__)


class AuthService:
    """
    Serviço para autenticação de usuários.

    Esta classe implementa a lógica de negócios relacionada à
    autenticação de usuários, incluindo registro, login e refresh token.
    """

    def __init__(self, db_session: Session):
        """
        Inicializa o serviço com uma sessão de banco de dados.

        Args:
            db_session: Sessão SQLAlchemy ativa
        """
        self.db = db_session

    def register_user(self, user_input: UserCreate) -> UserOutput:
        """
        Registra um novo usuário no sistema.

        Args:
            user_input: Dados do usuário a ser registrado

        Returns:
            Usuário registrado

        Raises:
            ResourceAlreadyExistsException: Se o email já estiver em uso
        """
        # Call the repository to create the user
        user = user_repository.create_with_password(self.db, obj_in=user_input)

        # Convert to DTO for response
        return UserOutput.from_orm(user)

    def login_user(self, user_input: UserCreate) -> TokenData:
        """
        Autentica um usuário e gera tokens de acesso e atualização.

        Args:
            user_input: Credenciais do usuário

        Returns:
            Dados do token de acesso e refresh

        Raises:
            InvalidCredentialsException: Se as credenciais forem inválidas
        """
        # Autenticar usuário
        user = user_repository.authenticate(
            self.db,
            email=user_input.email,
            password=user_input.password
        )

        # Generate token payload using domain service
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        token_id = str(uuid.uuid4())

        # Gerar tokens
        access_token = UserAuthManager.create_access_token(
            subject=str(user.id),
            expires_delta=access_token_expires
        )

        # Gerar refresh token com um identificador único
        refresh_token = UserAuthManager.create_refresh_token(
            subject=str(user.id),
            token_id=token_id,
            expires_delta=refresh_token_expires
        )

        # Calcular a data de expiração para enviar ao cliente
        expires_at = datetime.utcnow() + access_token_expires

        # Return token data
        return TokenData(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at
        )

    def refresh_token(self, refresh_token: str) -> TokenData:
        """
        Gera um novo token de acesso a partir de um refresh token válido.

        Args:
            refresh_token: Token de atualização

        Returns:
            Novos tokens de acesso e atualização

        Raises:
            InvalidCredentialsException: Se o refresh token for inválido
        """
        try:
            # Verify the refresh token
            payload = UserAuthManager.verify_refresh_token(refresh_token)
            user_id = payload.get("sub")
            token_id = payload.get("jti")

            if not user_id or not token_id:
                raise InvalidCredentialsException(detail="Token de atualização inválido")

            # Verify user exists and is active
            user = user_repository.get(self.db, id=user_id)
            if not user or not user.is_active:
                raise InvalidCredentialsException(detail="Usuário não encontrado ou inativo")

            # Generate new tokens
            access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            new_token_id = str(uuid.uuid4())

            new_access_token = UserAuthManager.create_access_token(
                subject=str(user.id),
                expires_delta=access_token_expires
            )

            new_refresh_token = UserAuthManager.create_refresh_token(
                subject=str(user.id),
                token_id=new_token_id,
                expires_delta=refresh_token_expires
            )

            # Calculate expiration time for response
            expires_at = datetime.utcnow() + access_token_expires

            # Return new token data
            return TokenData(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_at=expires_at
            )

        except InvalidCredentialsException:
            # Pass through the exception
            raise

        except Exception as e:
            logger.exception(f"Erro ao renovar token: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao processar refresh token",
                original_error=e
            )
