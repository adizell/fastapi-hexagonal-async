# app/adapters/inbound/api/v1/endpoints/auth_endpoint.py (async version)

import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.use_cases.auth_use_cases import AsyncAuthService
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

# Bearer scheme to extract token from Authorization header
bearer_scheme = HTTPBearer()


@router.post(
    "/register",
    response_model=UserOutput,
    status_code=status.HTTP_201_CREATED,
    summary="Register User - Creates a new user",
    description="""
    Creates a new user with email address. A client JWT token is required.

    The password must meet the following criteria:
    - Minimum of 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (such as !@#$%^&*)
    """,
    responses={
        201: {
            "description": "User created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "email": "user@example.com",
                        "is_active": True,
                        "is_superuser": False,
                        "created_at": "2023-01-01T00:00:00.000Z",
                        "updated_at": None
                    }
                }
            }
        },
        401: {
            "description": "Not authenticated or invalid client token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid or expired client token."
                    }
                }
            }
        },
        409: {
            "description": "Email already in use",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User with email 'user@example.com' already exists"
                    }
                }
            }
        }
    }
)
async def register_user(
        user_input: UserCreate,
        db: AsyncSession = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        service = AsyncAuthService(db)
        return await service.register_user(user_input)

    except ResourceAlreadyExistsException as e:
        # Use e.detail or str(e) to send the correct message
        msg = getattr(e, "detail", None) or str(e)
        logger.warning(f"Duplicate registration: {msg}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=msg
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Unhandled error in registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error."
        )


@router.post(
    "/login",
    response_model=TokenData,
    summary="Login User - Generates access token",
    description=(
            "Authenticates a user (email/password) and returns a JWT token. "
            "Login attempts with inactive users will result in an error. "
            "Requires a valid client token."
    ),
)
async def login_user(
        user_input: UserCreate,
        db: AsyncSession = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        service = AsyncAuthService(db)
        return await service.login_user(user_input)

    except InvalidCredentialsException as e:
        logger.warning(f"Invalid credentials: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.details,
            headers={"WWW-Authenticate": "Bearer"},
        )

    except ResourceInactiveException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user account. Contact the administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.exception(f"Unhandled error in login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error."
        )


@router.post(
    "/refresh",
    response_model=TokenData,
    summary="Refresh Token - Renews the access token",
    description=(
            "Generates a new access token from a valid refresh token. "
            "Requires a valid client token."
    ),
)
async def refresh_token(
        refresh_data: RefreshTokenRequest,
        db: AsyncSession = Depends(get_session),
        _: str = Depends(get_current_client),
):
    try:
        service = AsyncAuthService(db)
        return await service.refresh_token(refresh_data.refresh_token)

    except InvalidCredentialsException as e:
        logger.warning(f"Invalid refresh: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.details,
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.exception(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error."
        )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout - Revoke current access token",
    description="Invalidates the current access token by adding it to the blacklist.",
)
async def logout_user(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        db: AsyncSession = Depends(get_session),
):
    token = credentials.credentials
    try:
        # Decode to extract jti and exp
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token does not support revocation.",
            )
        expires_at = datetime.fromtimestamp(payload["exp"])

        # Add to blacklist
        from app.adapters.outbound.persistence.repositories.token_repository import token_repository
        await token_repository.add_to_blacklist(db, jti, expires_at)

        return {"detail": "Successfully logged out."}

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )
