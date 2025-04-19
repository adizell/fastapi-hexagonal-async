# app/adapters/inbound/api/deps.py (async version)

"""
Dependencies for injection into API endpoints.

This module defines functions that provide dependencies via
FastAPI Depends() for authentication, authorization, and database access.
"""

import logging
from uuid import UUID
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.outbound.persistence.database import get_db
from app.adapters.outbound.persistence.models.user_model import User
from app.adapters.outbound.persistence.models.client_model import Client
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.adapters.outbound.security.auth_client_manager import ClientAuthManager

# Configure logger
logger = logging.getLogger(__name__)

# Create bearer scheme for authentication
bearer_scheme = HTTPBearer()

########################################################################
# Database Session Management
########################################################################

# Aliases for get_db for backward compatibility
get_session = get_db
get_db_session = get_db


########################################################################
# Client Token Authentication
########################################################################

async def verify_client_token(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> str:
    """
    Verify and decode a client JWT token.

    Args:
        credentials: Authorization credentials with bearer token

    Returns:
        Client ID (sub) contained in the token

    Raises:
        HTTPException: If the token is invalid or expired
    """
    token = credentials.credentials
    payload = await ClientAuthManager.verify_client_token(token)
    sub = payload.get("sub")
    if not sub:
        logger.warning(f"Invalid token: 'sub' not found in client token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: 'sub' not found in client token.",
        )
    return sub


async def get_current_client(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: AsyncSession = Depends(get_db),
) -> Client:
    """
    Get the current client from the token.

    Args:
        credentials: Authorization credentials with bearer token
        db: Async database session

    Returns:
        Authenticated Client object

    Raises:
        HTTPException: If the token is invalid or the client doesn't exist/is inactive
    """
    try:
        token = credentials.credentials
        payload = await ClientAuthManager.verify_client_token(token)
        client_id = payload.get("sub")

        try:
            client_id = int(client_id)
        except (ValueError, TypeError):
            logger.warning(f"Invalid client token: 'sub' is not an integer ({client_id})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client token: 'sub' is not an integer.",
            )

        query = select(Client).where(
            Client.id == client_id,
            Client.is_active.is_(True)
        )
        result = await db.execute(query)
        client = result.scalar_one_or_none()

        if not client:
            logger.warning(f"Client ID {client_id} not found or inactive")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client not found or inactive.",
            )
        return client

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Unexpected error authenticating client: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client authentication error.",
        )


########################################################################
# User Token Authentication
########################################################################

async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get the current user from the token.

    Args:
        credentials: Authorization credentials with bearer token
        db: Async database session

    Returns:
        Authenticated User object

    Raises:
        HTTPException: If the token is invalid or the user doesn't exist/is inactive
    """
    try:
        token = credentials.credentials
        # Pass db to verify_access_token
        payload = await UserAuthManager.verify_access_token(token, db=db)

        try:
            user_id = UUID(payload.get("sub"))
        except (ValueError, TypeError):
            logger.warning(f"Invalid token: 'sub' is not a valid UUID ({payload.get('sub')})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: 'sub' is not a valid UUID.",
            )

        query = select(User).where(
            User.id == user_id,
            User.is_active.is_(True)
        )
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(f"User {user_id} not found or inactive")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive.",
            )
        return user

    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"Unexpected error authenticating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User authentication error.",
        )
