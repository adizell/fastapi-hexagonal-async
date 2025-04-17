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

from app.adapters.configuration.config import settings
from app.adapters.outbound.persistence.repositories.user_repository import user as user_repository
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.application.dtos.user_dto import UserCreate, TokenData
from app.domain.exceptions import InvalidCredentialsException, DatabaseOperationException

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

    def register_user(self, user_input: UserCreate):
        """
        Registra um novo usuário no sistema.

        Args:
            user_input: Dados do usuário a ser registrado

        Returns:
            Usuário registrado
        """
        return user_repository.create_with_password(self.db, obj_in=user_input)

    def login_user(self, user_input: UserCreate) -> TokenData:
        """
        Autentica um usuário e gera tokens de acesso e atualização.

        Args:
            user_input: Credenciais do usuário

        Returns:
            Dados do token de acesso e refresh
        """
        # Autenticar usuário
        user = user_repository.authenticate(
            self.db,
            email=user_input.email,
            password=user_input.password
        )

        # Gerar tokens
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        access_token = UserAuthManager.create_access_token(
            subject=str(user.id),
            expires_delta=access_token_expires
        )

        # Gerar refresh token com um identificador único
        refresh_token = UserAuthManager.create_refresh_token(
            subject=str(user.id),
            token_id=str(uuid.uuid4()),
            expires_delta=refresh_token_expires
        )

        # Calcular a data de expiração para enviar ao cliente
        expires_at = datetime.utcnow() + access_token_expires

        # Armazenar o refresh token no banco (opcional)
        # self._store_refresh_token(user.id, refresh_token, expires_at + refresh_token_expires)

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
            InvalidCredentialsException: Se o refresh token for inválido ou expirado
        """
        try:
            # Verificar o refresh token
            payload = UserAuthManager.verify_refresh_token(refresh_token)
            user_id = payload.get("sub")
            token_id = payload.get("jti")

            if not user_id or not token_id:
                raise InvalidCredentialsException(detail="Token de atualização inválido")

            # Verificar se o usuário existe e está ativo
            user = user_repository.get(self.db, id=user_id)
            if not user or not user.is_active:
                raise InvalidCredentialsException(detail="Usuário não encontrado ou inativo")

            # Verificar se o token não foi revogado (implementação opcional)
            # self._check_token_not_revoked(token_id)

            # Gerar novos tokens
            access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

            new_access_token = UserAuthManager.create_access_token(
                subject=str(user.id),
                expires_delta=access_token_expires
            )

            # Gerar novo refresh token
            new_refresh_token = UserAuthManager.create_refresh_token(
                subject=str(user.id),
                token_id=str(uuid.uuid4()),
                expires_delta=refresh_token_expires
            )

            # Calcular a data de expiração para enviar ao cliente
            expires_at = datetime.utcnow() + access_token_expires

            # Opcional: Revogar o token antigo e armazenar o novo
            # self._revoke_refresh_token(token_id)
            # self._store_refresh_token(user.id, new_refresh_token, expires_at + refresh_token_expires)

            return TokenData(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_at=expires_at
            )

        except InvalidCredentialsException:
            # Repassar exceção já formatada
            raise

        except Exception as e:
            logger.exception(f"Erro ao renovar token: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao processar refresh token",
                original_error=e
            )
