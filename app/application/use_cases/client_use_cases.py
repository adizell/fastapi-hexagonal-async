# app/application/use_cases/client_use_cases.py

"""
Serviço para gerenciamento de clientes.

Este módulo implementa o serviço para operações com clientes da API,
incluindo autenticação e gerenciamento de credenciais.
"""

import secrets
import logging
from typing import Dict
from datetime import timedelta, datetime
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.adapters.outbound.persistence.models import Client
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager
from app.adapters.outbound.security.token_store import TokenStore
from app.application.ports.inbound import IClientUseCase
from app.domain.exceptions import (
    ResourceNotFoundException,
    InvalidCredentialsException,
    DatabaseOperationException,
    ResourceInactiveException
)

logger = logging.getLogger(__name__)


class ClientService(IClientUseCase):
    """
    Serviço para gerenciamento de clientes.

    Esta classe implementa a lógica de negócios relacionada à
    manipulação de clientes da API, incluindo login e geração de tokens.
    """

    def __init__(self, db_session: Session):
        self.db_session = db_session

    def authenticate_client(self, admin_password: str) -> None:
        """
        Valida a senha administrativa para permitir operações de
        criação/atualização de clientes.
        """
        if not TokenStore.validate(admin_password, ClientAuthManager.crypt_context):
            logger.warning("Tentativa com senha administrativa inválida")
            raise InvalidCredentialsException(detail="Senha administrativa inválida")

    def client_login(self, client_id: str, client_secret: str, expires_in: int = None) -> str:
        try:
            client_db = (
                self.db_session
                .query(Client)
                .filter_by(client_id=client_id)
                .first()
            )

            if not client_db:
                logger.warning(f"Client ID não encontrado no login: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de cliente inválidas")

            if not ClientAuthManager.verify_password(client_secret, client_db.client_secret):
                logger.warning(f"Senha incorreta no login de cliente: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de cliente inválidas")

            if not client_db.is_active:
                logger.warning(f"Tentativa de login com cliente inativo: {client_id}")
                raise ResourceInactiveException(
                    detail="Este cliente está inativo e não tem permissão de acesso",
                    resource_id=client_db.id
                )

            expires_delta = timedelta(days=expires_in) if expires_in is not None else None
            token = ClientAuthManager.create_client_token(
                subject=str(client_db.id),
                expires_delta=expires_delta
            )

            logger.info(f"Login de cliente bem‑sucedido: {client_id}")
            return token

        except (InvalidCredentialsException, ResourceInactiveException):
            raise

        except Exception as e:
            logger.exception(f"Erro no login de cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro durante o processo de login do cliente",
                original_error=e
            )

    def create_client(self, admin_password: str) -> Dict[str, str]:
        """
        Cria um novo cliente. Recebe a senha administrativa,
        valida, gera e persiste client_id e client_secret (hash).
        Retorna as credenciais em texto claro.
        """
        try:
            # primeiro valida a senha administrativa
            self.authenticate_client(admin_password)

            client_id = secrets.token_urlsafe(16)
            plain_secret = secrets.token_urlsafe(32)
            hashed = ClientAuthManager.hash_password(plain_secret)

            new_client = Client(
                client_id=client_id,
                client_secret=hashed,
                is_active=True,
                created_at=datetime.utcnow()
            )

            self.db_session.add(new_client)
            self.db_session.commit()
            self.db_session.refresh(new_client)

            logger.info(f"Novo cliente criado com ID: {client_id}")
            return {"client_id": client_id, "client_secret": plain_secret}

        except SQLAlchemyError as e:
            self.db_session.rollback()
            logger.error(f"Erro de banco ao criar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro ao criar cliente",
                original_error=e
            )

    def update_client_secret(self, client_id: str, admin_password: str) -> Dict[str, str]:
        """
        Atualiza a chave secreta de um cliente existente.
        Exige senha administrativa.
        """
        try:
            self.authenticate_client(admin_password)

            client_db = (
                self.db_session
                .query(Client)
                .filter_by(client_id=client_id)
                .first()
            )
            if not client_db:
                logger.warning(f"Tentativa de atualizar cliente inexistente: {client_id}")
                raise ResourceNotFoundException(
                    detail="Cliente não encontrado",
                    resource_id=client_id
                )

            if not client_db.is_active:
                logger.warning(f"Tentativa de atualizar cliente inativo: {client_id}")
                raise ResourceInactiveException(
                    detail="Este cliente está inativo e não pode ser atualizado",
                    resource_id=client_db.id
                )

            new_plain = secrets.token_urlsafe(32)
            client_db.client_secret = ClientAuthManager.hash_password(new_plain)

            self.db_session.commit()
            self.db_session.refresh(client_db)

            logger.info(f"Chave secreta atualizada para cliente: {client_id}")
            return {"client_id": client_id, "new_client_secret": new_plain}

        except (ResourceNotFoundException, ResourceInactiveException):
            self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            self.db_session.rollback()
            logger.error(f"Erro de banco ao atualizar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar cliente",
                original_error=e
            )

    def get_client_by_id(self, client_id: str) -> Client:
        client = (
            self.db_session
            .query(Client)
            .filter_by(client_id=client_id)
            .first()
        )
        if not client:
            logger.warning(f"Cliente não encontrado: ID {client_id}")
            raise ResourceNotFoundException(
                detail=f"Cliente com ID {client_id} não encontrado",
                resource_id=client_id
            )
        if not client.is_active:
            logger.warning(f"Tentativa de acessar cliente inativo: ID {client_id}")
            raise ResourceInactiveException(
                detail="Este cliente está inativo e não está disponível",
                resource_id=client_id
            )
        return client
