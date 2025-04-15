# app/adapters/outbound/persistence/repositories/client_crud.py

"""
Repositório CRUD para clientes.

Este módulo implementa operações específicas de banco de dados
para a entidade Client, estendendo a funcionalidade básica do CRUDBase.
Um client representa uma aplicação/sistema que pode acessar a API.
"""

import secrets
from typing import Optional, List, Dict
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.adapters.outbound.persistence.repositories.base_repositories import CRUDBase
from app.adapters.outbound.persistence.models import Client
from app.application.dtos.client_schemas import Client as ClientSchema
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager
from app.domain.exceptions import (
    ResourceNotFoundException,
    DatabaseOperationException,
    InvalidCredentialsException
)


class ClientCRUD(CRUDBase[Client, ClientSchema, ClientSchema]):
    """
    Implementação do repositório CRUD para a entidade Client.

    Estende CRUDBase com operações específicas para clients,
    como busca por client_id e geração de credenciais.
    """

    def get_by_client_id(self, db: Session, client_id: str) -> Optional[Client]:
        """
        Busca um client pelo client_id.

        Args:
            db: Sessão do banco de dados
            client_id: Identificador do client

        Returns:
            Client encontrado ou None se não existir

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            return db.query(Client).filter(Client.client_id == client_id).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao buscar client por client_id '{client_id}': {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao buscar client por client_id",
                original_error=e
            )

    def create_client(self, db: Session) -> Dict[str, str]:
        """
        Cria um novo client com credenciais geradas automaticamente.

        Args:
            db: Sessão do banco de dados

        Returns:
            Dicionário com client_id e client_secret

        Raises:
            DatabaseOperationException: Se ocorrer erro na criação
        """
        try:
            # Gerar credenciais
            client_id = secrets.token_urlsafe(16)
            client_secret_plain = secrets.token_urlsafe(32)
            client_secret_hash = ClientAuthManager.hash_password(client_secret_plain)

            # Criar objeto do client
            client = Client(
                client_id=client_id,
                client_secret=client_secret_hash,
                is_active=True
            )

            # Salvar no banco
            db.add(client)
            db.commit()
            db.refresh(client)

            self.logger.info(f"Client criado: {client.id} (client_id: {client_id})")

            # Retornar credenciais para uso imediato (o segredo não fica armazenado em texto plano)
            return {
                "client_id": client_id,
                "client_secret": client_secret_plain  # Esta é a única vez que o secret é exposto
            }

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao criar client: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao criar client",
                original_error=e
            )

    def update_client_secret(self, db: Session, client_id: str) -> Dict[str, str]:
        """
        Atualiza a chave secreta de um client existente.

        Args:
            db: Sessão do banco de dados
            client_id: Identificador do client

        Returns:
            Dicionário com client_id e nova client_secret

        Raises:
            ResourceNotFoundException: Se o client não existir
            DatabaseOperationException: Se ocorrer erro na atualização
        """
        try:
            # Buscar o client
            client = self.get_by_client_id(db, client_id)
            if not client:
                raise ResourceNotFoundException(
                    detail=f"Client com ID '{client_id}' não encontrado",
                    resource_id=client_id
                )

            # Gerar nova chave secreta
            new_secret_plain = secrets.token_urlsafe(32)
            new_secret_hash = ClientAuthManager.hash_password(new_secret_plain)

            # Atualizar a chave no banco
            client.client_secret = new_secret_hash

            # Salvar alterações
            db.add(client)
            db.commit()
            db.refresh(client)

            self.logger.info(f"Chave secreta atualizada para client {client_id}")

            # Retornar nova chave para uso imediato
            return {
                "client_id": client_id,
                "new_client_secret": new_secret_plain  # Esta é a única vez que o secret é exposto
            }

        except ResourceNotFoundException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao atualizar chave secreta do client: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar chave secreta do client",
                original_error=e
            )

    def authenticate_client(self, db: Session, client_id: str, client_secret: str) -> Client:
        """
        Autentica um client verificando client_id e client_secret.

        Args:
            db: Sessão do banco de dados
            client_id: Identificador do client
            client_secret: Chave secreta em texto plano

        Returns:
            Client autenticado

        Raises:
            InvalidCredentialsException: Se as credenciais forem inválidas
            DatabaseOperationException: Se ocorrer erro na autenticação
        """
        try:
            # Buscar o client
            client = self.get_by_client_id(db, client_id)
            if not client:
                self.logger.warning(f"Tentativa de autenticação com client_id inexistente: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de client inválidas")

            # Verificar se o client está ativo
            if not client.is_active:
                self.logger.warning(f"Tentativa de autenticação com client inativo: {client_id}")
                raise InvalidCredentialsException(detail="Client está inativo")

            # Verificar a senha
            if not ClientAuthManager.verify_password(client_secret, client.client_secret):
                self.logger.warning(f"Tentativa de autenticação com senha incorreta: {client_id}")
                raise InvalidCredentialsException(detail="Credenciais de client inválidas")

            return client

        except InvalidCredentialsException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao autenticar client: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao autenticar client",
                original_error=e
            )

    def toggle_status(self, db: Session, client_id: str, active: bool) -> Client:
        """
        Ativa ou desativa um client.

        Args:
            db: Sessão do banco de dados
            client_id: Identificador do client
            active: Novo status (True=ativo, False=inativo)

        Returns:
            Client atualizado

        Raises:
            ResourceNotFoundException: Se o client não existir
            DatabaseOperationException: Se ocorrer erro na atualização
        """
        try:
            # Buscar o client
            client = self.get_by_client_id(db, client_id)
            if not client:
                raise ResourceNotFoundException(
                    detail=f"Client com ID '{client_id}' não encontrado",
                    resource_id=client_id
                )

            # Atualizar status
            client.is_active = active

            # Salvar alterações
            db.add(client)
            db.commit()
            db.refresh(client)

            status_text = "ativado" if active else "desativado"
            self.logger.info(f"Client {client_id} {status_text}")
            return client

        except ResourceNotFoundException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao alterar status do client: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao {'ativar' if active else 'desativar'} client",
                original_error=e
            )

    def list_active_clients(self, db: Session, skip: int = 0, limit: int = 100) -> List[Client]:
        """
        Lista clients ativos.

        Args:
            db: Sessão do banco de dados
            skip: Registros a pular (para paginação)
            limit: Máximo de registros a retornar

        Returns:
            Lista de clients ativos

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            return db.query(Client) \
                .filter(Client.is_active == True) \
                .order_by(Client.client_id) \
                .offset(skip) \
                .limit(limit) \
                .all()

        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao listar clients ativos: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao listar clients ativos",
                original_error=e
            )


# Instância singleton do CRUD para ser usada pelos serviços
client = ClientCRUD(Client)
