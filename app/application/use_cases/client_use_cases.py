# app/application/use_cases/client_use_cases.py (async version)

"""
Service for client management.

This module implements the service for operations with API clients,
including authentication and credential management.
"""

import secrets
import logging
from typing import Dict
from datetime import timedelta, datetime
from sqlalchemy.ext.asyncio import AsyncSession
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
from app.adapters.outbound.persistence.repositories.client_repository import client_repository

logger = logging.getLogger(__name__)


class AsyncClientService(IClientUseCase):
    """
    Service for client management.

    This class implements the business logic related to
    API client management, including login and token generation.
    """

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def authenticate_client(self, admin_password: str) -> None:
        """
        Validates the administrative password to allow client
        creation/update operations.
        """
        if not TokenStore.validate(admin_password, ClientAuthManager.crypt_context):
            logger.warning("Attempt with invalid administrative password")
            raise InvalidCredentialsException(detail="Invalid administrative password")

    async def client_login(self, client_id: str, client_secret: str, expires_in: int = None) -> str:
        try:
            from sqlalchemy.future import select
            query = select(Client).where(Client.client_id == client_id)
            result = await self.db_session.execute(query)
            client_db = result.scalar_one_or_none()

            if not client_db:
                logger.warning(f"Client ID not found in login: {client_id}")
                raise InvalidCredentialsException(detail="Invalid client credentials")

            if not await ClientAuthManager.verify_password(client_secret, client_db.client_secret):
                logger.warning(f"Incorrect password in client login: {client_id}")
                raise InvalidCredentialsException(detail="Invalid client credentials")

            if not client_db.is_active:
                logger.warning(f"Login attempt with inactive client: {client_id}")
                raise ResourceInactiveException(
                    detail="This client is inactive and does not have access permission",
                    resource_id=client_db.id
                )

            expires_delta = timedelta(days=expires_in) if expires_in is not None else None
            token = await ClientAuthManager.create_client_token(
                subject=str(client_db.id),
                expires_delta=expires_delta
            )

            logger.info(f"Successful client login: {client_id}")
            return token

        except (InvalidCredentialsException, ResourceInactiveException):
            raise

        except Exception as e:
            logger.exception(f"Error in client login: {e}")
            raise DatabaseOperationException(
                detail="Error during client login process",
                original_error=e
            )

    async def create_client(self, admin_password: str) -> Dict[str, str]:
        """
        Creates a new client. Receives the administrative password,
        validates, generates and persists client_id and client_secret (hash).
        Returns the credentials in plain text.
        """
        try:
            # First validate the administrative password
            await self.authenticate_client(admin_password)

            # Generate credentials and create client
            return await client_repository.create_with_credentials(self.db_session)

        except SQLAlchemyError as e:
            await self.db_session.rollback()
            logger.error(f"Database error creating client: {e}")
            raise DatabaseOperationException(
                detail="Error creating client",
                original_error=e
            )

    async def update_client_secret(self, client_id: str, admin_password: str) -> Dict[str, str]:
        """
        Updates the secret key of an existing client.
        Requires administrative password.
        """
        try:
            await self.authenticate_client(admin_password)
            return await client_repository.update_secret(self.db_session, client_id)

        except (ResourceNotFoundException, ResourceInactiveException):
            await self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            await self.db_session.rollback()
            logger.error(f"Database error updating client: {e}")
            raise DatabaseOperationException(
                detail="Error updating client",
                original_error=e
            )

    async def get_client_by_id(self, client_id: str) -> Client:
        client = await client_repository.get_by_client_id(self.db_session, client_id)
        if not client:
            logger.warning(f"Client not found: ID {client_id}")
            raise ResourceNotFoundException(
                detail=f"Client with ID {client_id} not found",
                resource_id=client_id
            )
        if not client.is_active:
            logger.warning(f"Attempt to access inactive client: ID {client_id}")
            raise ResourceInactiveException(
                detail="This client is inactive and not available",
                resource_id=client_id
            )
        return client
