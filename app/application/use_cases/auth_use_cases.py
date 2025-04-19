# app/application/use_cases/auth_use_cases.py (async version)

"""
Service for user authentication.

This module implements the service for authentication operations,
including registration, login, and token renewal.
"""

import logging
import uuid
from datetime import timezone
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.configuration.config import settings
from app.adapters.outbound.persistence.repositories.user_repository import user_repository
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.application.dtos.user_dto import UserCreate, TokenData, UserOutput
from app.domain.exceptions import InvalidCredentialsException, DatabaseOperationException

logger = logging.getLogger(__name__)


class AsyncAuthService:
    """
    Service for user authentication.

    This class implements the business logic related to
    user authentication, including registration, login, and token refresh.
    """

    def __init__(self, db_session: AsyncSession):
        """
        Initialize the service with a database session.

        Args:
            db_session: Active SQLAlchemy session
        """
        self.db = db_session

    async def register_user(self, user_input: UserCreate) -> UserOutput:
        """
        Register a new user in the system.

        Args:
            user_input: User data to register

        Returns:
            Registered user

        Raises:
            ResourceAlreadyExistsException: If the email is already in use
        """
        # Call the repository to create the user
        user = await user_repository.create_with_password(self.db, obj_in=user_input)

        # Convert to DTO for response
        return UserOutput.model_validate(user)

    async def login_user(self, user_input: UserCreate) -> TokenData:
        """
        Authenticate a user and generate access and refresh tokens.

        Args:
            user_input: User credentials

        Returns:
            Token data with access and refresh tokens

        Raises:
            InvalidCredentialsException: If credentials are invalid
        """
        # Authenticate user
        user = await user_repository.authenticate(
            self.db,
            email=user_input.email,
            password=user_input.password
        )

        # Generate token payload using domain service
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        token_id = str(uuid.uuid4())

        # Generate tokens
        access_token = await UserAuthManager.create_access_token(
            subject=str(user.id),
            expires_delta=access_token_expires
        )

        # Generate refresh token with a unique identifier
        refresh_token = await UserAuthManager.create_refresh_token(
            subject=str(user.id),
            token_id=token_id,
            expires_delta=refresh_token_expires
        )

        # Calculate expiration date to send to client
        expires_at = datetime.now(timezone.utc) + access_token_expires

        # Return token data
        return TokenData(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at
        )

    async def refresh_token(self, refresh_token: str) -> TokenData:
        """
        Generate a new access token from a valid refresh token.

        Args:
            refresh_token: Refresh token

        Returns:
            New access and refresh tokens

        Raises:
            InvalidCredentialsException: If the refresh token is invalid
        """
        try:
            # Verify the refresh token
            payload = await UserAuthManager.verify_refresh_token(refresh_token)
            user_id = payload.get("sub")
            token_id = payload.get("jti")

            if not user_id or not token_id:
                raise InvalidCredentialsException(detail="Invalid refresh token")

            # Verify user exists and is active
            user = await user_repository.get(self.db, id=user_id)
            if not user or not user.is_active:
                raise InvalidCredentialsException(detail="User not found or inactive")

            # Generate new tokens
            access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_USER_EXPIRE_MINUTOS)
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            new_token_id = str(uuid.uuid4())

            new_access_token = await UserAuthManager.create_access_token(
                subject=str(user.id),
                expires_delta=access_token_expires
            )

            new_refresh_token = await UserAuthManager.create_refresh_token(
                subject=str(user.id),
                token_id=new_token_id,
                expires_delta=refresh_token_expires
            )

            # Calculate expiration time for response
            expires_at = datetime.now(timezone.utc) + access_token_expires

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
            logger.exception(f"Error refreshing token: {str(e)}")
            raise DatabaseOperationException(
                detail="Error processing refresh token",
                original_error=e
            )
