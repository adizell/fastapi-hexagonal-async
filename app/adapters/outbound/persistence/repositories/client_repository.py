# app/adapters/outbound/persistence/repositories/client_repository.py (async version)

"""
Repository for client operations.

This module implements the repository that performs database operations
related to clients, implementing the IClientRepository interface.
"""

import secrets
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError

from app.adapters.outbound.persistence.repositories.base_repository import AsyncCRUDBase
from app.adapters.outbound.persistence.models import Client
from app.application.dtos.client_dto import Client as ClientSchema
from app.application.ports.outbound import IClientRepository
from app.domain.models.client_domain_model import Client as DomainClient
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager
from app.domain.exceptions import (
    ResourceNotFoundException,
    DatabaseOperationException,
    InvalidCredentialsException
)


class AsyncClientCRUD(AsyncCRUDBase[Client, ClientSchema, ClientSchema], IClientRepository):
    """
    Async implementation of CRUD repository for the Client entity.

    Extends AsyncCRUDBase with client-specific operations,
    such as lookup by client_id and credential generation.
    """

    async def get_by_client_id(self, db: AsyncSession, client_id: str) -> Optional[Client]:
        """
        Find a client by client_id.

        Args:
            db: Async database session
            client_id: Client identifier

        Returns:
            Client found or None if it doesn't exist

        Raises:
            DatabaseOperationException: In case of database error
        """
        try:
            query = select(Client).where(Client.client_id == client_id)
            result = await db.execute(query)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            self.logger.error(f"Error fetching client by client_id '{client_id}': {str(e)}")
            raise DatabaseOperationException(
                detail="Error fetching client by client_id",
                original_error=e
            )

    async def create_with_credentials(self, db: AsyncSession) -> Dict[str, str]:
        """
        Create a new client with automatically generated credentials.

        Args:
            db: Async database session

        Returns:
            Dictionary with client_id and client_secret

        Raises:
            DatabaseOperationException: In case of database error
        """
        try:
            # Generate credentials
            client_id = secrets.token_urlsafe(16)
            client_secret_plain = secrets.token_urlsafe(32)
            client_secret_hash = await ClientAuthManager.hash_password(client_secret_plain)

            # Create client object
            client = Client(
                client_id=client_id,
                client_secret=client_secret_hash,
                is_active=True
            )

            # Save to database
            db.add(client)
            await db.commit()
            await db.refresh(client)

            self.logger.info(f"Client created: {client.id} (client_id: {client_id})")

            # Return credentials for immediate use (the secret is not stored in plain text)
            return {
                "client_id": client_id,
                "client_secret": client_secret_plain  # This is the only time the secret is exposed
            }

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error creating client: {str(e)}")
            raise DatabaseOperationException(
                detail="Error creating client",
                original_error=e
            )

    async def update_secret(self, db: AsyncSession, client_id: str) -> Dict[str, str]:
        """
        Update the secret key of an existing client.

        Args:
            db: Async database session
            client_id: Client identifier

        Returns:
            Dictionary with client_id and new client_secret

        Raises:
            ResourceNotFoundException: If the client doesn't exist
            DatabaseOperationException: In case of database error
        """
        try:
            # Find the client
            client = await self.get_by_client_id(db, client_id)
            if not client:
                raise ResourceNotFoundException(
                    detail=f"Client with ID '{client_id}' not found",
                    resource_id=client_id
                )

            # Generate new secret key
            new_secret_plain = secrets.token_urlsafe(32)
            new_secret_hash = await ClientAuthManager.hash_password(new_secret_plain)

            # Update the key in the database
            client.client_secret = new_secret_hash

            # Save changes
            db.add(client)
            await db.commit()
            await db.refresh(client)

            self.logger.info(f"Secret key updated for client {client_id}")

            # Return new key for immediate use
            return {
                "client_id": client_id,
                "new_client_secret": new_secret_plain  # This is the only time the secret is exposed
            }

        except ResourceNotFoundException:
            # Pass through the already formatted exception
            raise

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error updating client secret key: {str(e)}")
            raise DatabaseOperationException(
                detail="Error updating client secret key",
                original_error=e
            )

    async def authenticate_client(self, db: AsyncSession, client_id: str, client_secret: str) -> Client:
        """
        Authenticate a client by verifying client_id and client_secret.

        Args:
            db: Async database session
            client_id: Client identifier
            client_secret: Plain text secret key

        Returns:
            Authenticated Client

        Raises:
            InvalidCredentialsException: If credentials are invalid
            DatabaseOperationException: In case of database error
        """
        try:
            # Find the client
            client = await self.get_by_client_id(db, client_id)
            if not client:
                self.logger.warning(f"Authentication attempt with non-existent client_id: {client_id}")
                raise InvalidCredentialsException(detail="Invalid client credentials")

            # Check if the client is active
            if not client.is_active:
                self.logger.warning(f"Authentication attempt with inactive client: {client_id}")
                raise InvalidCredentialsException(detail="Client is inactive")

            # Verify the password
            if not await ClientAuthManager.verify_password(client_secret, client.client_secret):
                self.logger.warning(f"Authentication attempt with incorrect password: {client_id}")
                raise InvalidCredentialsException(detail="Invalid client credentials")

            return client

        except InvalidCredentialsException:
            # Pass through the already formatted exception
            raise

        except SQLAlchemyError as e:
            self.logger.error(f"Error authenticating client: {str(e)}")
            raise DatabaseOperationException(
                detail="Error authenticating client",
                original_error=e
            )

    def to_domain(self, db_model: Client) -> DomainClient:
        """
        Convert database model to domain model.

        Args:
            db_model: Client ORM model

        Returns:
            Domain model of client
        """
        return DomainClient(
            id=db_model.id,
            client_id=db_model.client_id,
            client_secret=db_model.client_secret,
            is_active=db_model.is_active,
            created_at=db_model.created_at,
            updated_at=db_model.updated_at
        )

    async def delete(self, db: AsyncSession, *, id: Any) -> None:
        """
        Delete a client by ID.

        Args:
            db: Async database session
            id: ID of the client to delete

        Raises:
            ResourceNotFoundException: If the client is not found
        """
        client = await self.get(db, id=id)
        if not client:
            raise ResourceNotFoundException(
                detail=f"Client with ID {id} not found",
                resource_id=id
            )

        await db.delete(client)
        await db.commit()
        return client

    async def list(self, db: AsyncSession, *, skip: int = 0, limit: int = 100, **filters) -> List[Client]:
        """
        List clients with optional filtering.

        Args:
            db: Async database session
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            **filters: Additional filters

        Returns:
            List of Client objects
        """
        return await self.get_multi(db, skip=skip, limit=limit, **filters)


# Public instance to be used by use cases
client_repository = AsyncClientCRUD(Client)
