# app/services/client_service.py

"""
Serviço para gerenciamento de clientes.

Este módulo implementa o serviço para operações com clientes da API,
incluindo autenticação e gerenciamento de credenciais.
"""

import secrets
import logging
from typing import Dict
from datetime import timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from passlib.context import CryptContext

from app.db.models.client import Client
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager
from app.core.exceptions import (
    ResourceNotFoundException,
    InvalidCredentialsException,
    DatabaseOperationException,
    ResourceInactiveException
)

# Configurar logger
logger = logging.getLogger(__name__)

# Configuração para hashing usando bcrypt
crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ClientService:
    """
    Serviço para gerenciamento de clientes.

    Esta classe implementa a lógica de negócios relacionada à
    manipulação de clientes da API, incluindo login e geração de tokens.
    """

    def __init__(self, db_session: Session):
        """
        Inicializa o serviço com uma sessão de banco de dados.

        Args:
            db_session: Sessão SQLAlchemy ativa
        """
        self.db_session = db_session

    def client_login(self, client_id: str, client_secret: str, expires_in: int = None) -> str:
        """
        Autentica um cliente e gera um token JWT.

        Args:
            client_id: Identificador do cliente
            client_secret: Senha do cliente
            expires_in: Tempo de expiração em dias (opcional)

        Returns:
            Token JWT

        Raises:
            InvalidCredentialsException: Se as credenciais forem inválidas
            ResourceInactiveException: Se o cliente estiver inativo
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            client_db = self.db_session.query(Client).filter_by(client_id=client_id).first()

            if client_db is None:
                logger.warning(f"Client ID não encontrado no login: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de cliente inválidas")

            if not ClientAuthManager.verify_password(client_secret, client_db.client_secret):
                logger.warning(f"Senha incorreta no login de cliente: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de cliente inválidas")

            # Verificar se o cliente está ativo - esta verificação deve existir, mas vamos garantir
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

            logger.info(f"Login de cliente bem-sucedido: {client_id}")
            return token

        except (InvalidCredentialsException, ResourceInactiveException):
            # Repassa exceções já formatadas
            raise

        except Exception as e:
            logger.exception(f"Erro no login de cliente: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro durante o processo de login do cliente",
                original_error=e
            )

    def create_client(self) -> Dict[str, str]:
        """
        Cria um novo cliente.

        Gera um client_id e um client_secret (em texto plano),
        armazena o hash do client_secret no banco e retorna as credenciais.

        Returns:
            dict: { "client_id": <client_id>, "client_secret": <client_secret_plain> }

        Raises:
            DatabaseOperationException: Se ocorrer erro ao salvar o novo client.
        """
        try:
            # Gerar identificadores únicos
            client_id = secrets.token_urlsafe(16)
            plain_client_secret = secrets.token_urlsafe(32)
            hashed_secret = crypt_context.hash(plain_client_secret)

            # Criar nova instância do client
            new_client = Client(
                client_id=client_id,
                client_secret=hashed_secret,
                is_active=True
            )

            # Persistir no banco de dados
            self.db_session.add(new_client)
            self.db_session.commit()
            self.db_session.refresh(new_client)

            logger.info(f"Novo cliente criado com ID: {client_id}")

            return {
                "client_id": client_id,
                "client_secret": plain_client_secret
            }

        except SQLAlchemyError as e:
            self.db_session.rollback()
            logger.error(f"Erro de banco de dados ao criar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro ao criar cliente",
                original_error=e
            )

        except Exception as e:
            self.db_session.rollback()
            logger.error(f"Erro inesperado ao criar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro interno ao criar cliente",
                original_error=e
            )

    def update_client_secret(self, client_id: str) -> Dict[str, str]:
        """
        Atualiza a chave secreta de um cliente.

        Busca o cliente pelo client_id, gera uma nova chave secreta,
        armazena o hash no banco e retorna a nova chave em texto plano.

        Args:
            client_id: O client_id do cliente (valor público).

        Returns:
            dict: { "client_id": <client_id>, "new_client_secret": <new_secret_plain> }

        Raises:
            ResourceNotFoundException: Se o cliente não for encontrado
            ResourceInactiveException: Se o cliente estiver inativo
            DatabaseOperationException: Se ocorrer erro na atualização.
        """
        try:
            # Busca o cliente pelo ID
            client_db = self.db_session.query(Client).filter_by(client_id=client_id).first()
            if client_db is None:
                logger.warning(f"Tentativa de atualizar cliente inexistente: {client_id}")
                raise ResourceNotFoundException(
                    detail="Cliente não encontrado",
                    resource_id=client_id
                )

            # Verificar se o cliente está ativo
            if not client_db.is_active:
                logger.warning(f"Tentativa de atualizar cliente inativo: {client_id}")
                raise ResourceInactiveException(
                    detail="Este cliente está inativo e não pode ser atualizado",
                    resource_id=client_db.id
                )

            # Gerar e atualizar a chave secreta
            new_secret_plain = secrets.token_urlsafe(32)
            new_secret_hashed = crypt_context.hash(new_secret_plain)
            client_db.client_secret = new_secret_hashed

            self.db_session.commit()
            logger.info(f"Chave secreta atualizada para cliente: {client_id}")

            return {
                "client_id": client_db.client_id,
                "new_client_secret": new_secret_plain
            }

        except (ResourceNotFoundException, ResourceInactiveException):
            # Repassar exceções já tratadas
            self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            self.db_session.rollback()
            logger.error(f"Erro de banco de dados ao atualizar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar cliente",
                original_error=e
            )

        except Exception as e:
            self.db_session.rollback()
            logger.error(f"Erro inesperado ao atualizar cliente: {e}")
            raise DatabaseOperationException(
                detail="Erro interno ao atualizar cliente",
                original_error=e
            )

    def get_client_by_id(self, client_id: str) -> Client:
        """
        Busca um cliente pelo ID e verifica se está ativo.

        Args:
            client_id: ID do cliente

        Returns:
            Cliente encontrado

        Raises:
            ResourceNotFoundException: Se o cliente não for encontrado
            ResourceInactiveException: Se o cliente estiver inativo
        """
        client = self.db_session.query(Client).filter_by(client_id=client_id).first()

        if not client:
            logger.warning(f"Cliente não encontrado: ID {client_id}")
            raise ResourceNotFoundException(
                detail=f"Cliente com ID {client_id} não encontrado",
                resource_id=client_id
            )

        # Verificar se o cliente está ativo
        if not client.is_active:
            logger.warning(f"Tentativa de acessar cliente inativo: ID {client_id}")
            raise ResourceInactiveException(
                detail="Este cliente está inativo e não está disponível",
                resource_id=client_id
            )

        return client
