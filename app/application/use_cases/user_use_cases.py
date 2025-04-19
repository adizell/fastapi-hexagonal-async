# app/application/use_cases/user_use_cases.py (async version)

"""
Service for user management.

This module implements the service for user operations,
including registration, authentication, updates, and profile management.
"""

from uuid import UUID
from datetime import datetime, timedelta
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_pagination import Params
from fastapi_pagination.ext.async_sqlalchemy import paginate

from app.adapters.outbound.persistence.models import User
from app.adapters.outbound.persistence.models import AuthGroup
from app.application.dtos.user_dto import UserCreate, UserUpdate, UserSelfUpdate, TokenData
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.adapters.outbound.persistence.repositories.user_repository import user_repository
from app.domain.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    InvalidCredentialsException,
    DatabaseOperationException,
    PermissionDeniedException,
    ResourceInactiveException
)
from app.domain.services.user_service import UserPermissionService

# Configure logger
logger = logging.getLogger(__name__)


class AsyncUserService:
    """
    Service for user management.

    This class implements the business logic related to
    user management, including authentication, authorization, and management.
    """

    def __init__(self, db_session: AsyncSession):
        """
        Initialize the service with a database session.

        Args:
            db_session: Active AsyncSession
        """
        self.db = db_session

    async def _get_user_by_id(self, user_id: UUID) -> User:
        """
        Get a user by ID or raise an exception if it doesn't exist.

        Args:
            user_id: User UUID

        Returns:
            User object

        Raises:
            ResourceNotFoundException: If the user is not found
            ResourceInactiveException: If the user is inactive
        """
        user = await user_repository.get(self.db, id=user_id)
        if not user:
            logger.warning(f"User not found: ID {user_id}")
            raise ResourceNotFoundException(
                detail="User not found",
                resource_id=user_id
            )

        # Check active status
        if not user.is_active:
            logger.warning(f"Attempt to access inactive user: ID {user_id}")
            raise ResourceInactiveException(
                detail="This user is inactive and not available",
                resource_id=user_id
            )

        return user

    async def _get_user_by_email(self, email: str) -> User:
        """
        Get a user by email or raise an exception if it doesn't exist.

        Args:
            email: User's email

        Returns:
            User object

        Raises:
            ResourceNotFoundException: If the user is not found
            ResourceInactiveException: If the user is inactive
        """
        user = await user_repository.get_by_email(self.db, email=email)
        if not user:
            logger.warning(f"User not found: email {email}")
            raise ResourceNotFoundException(
                detail="User not found with this email"
            )

        # Check active status
        if not user.is_active:
            logger.warning(f"Attempt to access inactive user: email {email}")
            raise ResourceInactiveException(
                detail="This user is inactive and not available"
            )

        return user

    async def _get_group_by_name(self, name: str) -> AuthGroup:
        """
        Return the permission group by name.

        Args:
            name: Group name

        Returns:
            AuthGroup object

        Raises:
            DatabaseOperationException: If the group is not found
        """
        from sqlalchemy.future import select
        query = select(AuthGroup).where(AuthGroup.name == name)
        result = await self.db.execute(query)
        group = result.scalar_one_or_none()

        if not group:
            error_msg = f"Group '{name}' not found. Check the initial seed."
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg)
        return group

    async def list_users(self, current_user: User, params: Params, order: str = "desc"):
        """
        Paginated list of users sorted by creation date.

        Args:
            current_user: Authenticated user
            params: Pagination parameters
            order: Sort direction (asc|desc)

        Returns:
            Paginated list of users

        Raises:
            PermissionDeniedException: If the user is not a superuser
            DatabaseOperationException: If there's an error in the process
        """
        try:
            # Check permission using domain service
            if not current_user.is_superuser:
                logger.warning(f"Non-privileged user attempted to list all users: {current_user.email}")
                raise PermissionDeniedException(
                    detail="Only superusers can list all users."
                )

            from sqlalchemy.future import select
            query = select(User)
            query = query.order_by(User.created_at.desc() if order == "desc" else User.created_at.asc())

            logger.info(f"User listing performed by: {current_user.email}")
            return await paginate(self.db, query, params)

        except PermissionDeniedException:
            # Pass through already formatted exception
            raise

        except Exception as e:
            logger.exception(f"Error listing users: {str(e)}")
            raise DatabaseOperationException(
                detail="Error listing users",
                original_error=e
            )

    async def update_self(self, user_id: UUID, data: UserSelfUpdate) -> User:
        """
        Allow a user to update their own profile.

        Args:
            user_id: User ID
            data: Data to be updated

        Returns:
            Updated user

        Raises:
            ResourceNotFoundException: If the user is not found
            ResourceInactiveException: If the user is inactive
            InvalidCredentialsException: If the current password is incorrect
            ResourceAlreadyExistsException: If the new email is already in use
            DatabaseOperationException: If there's an error in the process
        """
        try:
            # Use the method that already checks active status
            user = await self._get_user_by_id(user_id)

            # If trying to change password, check current password
            if data.password and not data.current_password:
                logger.warning(f"Attempt to change password without providing current password: {user.email}")
                raise InvalidCredentialsException(
                    detail="To change the password, you must provide the current password."
                )

            # Verify current password if provided
            if data.current_password:
                if not await UserAuthManager.verify_password(data.current_password, user.password):
                    logger.warning(f"Incorrect current password when updating user: {user.email}")
                    raise InvalidCredentialsException(
                        detail="Current password incorrect."
                    )

            # Update fields
            if data.email is not None and data.email != user.email:
                # Check if new email already exists
                from sqlalchemy.future import select
                query = select(User).where(
                    User.email == data.email,
                    User.id != user_id
                )
                result = await self.db.execute(query)
                existing = result.scalar_one_or_none()

                if existing:
                    logger.warning(f"Email already in use when updating user: {data.email}")
                    raise ResourceAlreadyExistsException(
                        detail="This email is already in use."
                    )

                user.email = data.email

            if data.password is not None:
                # Verify password strength using domain service
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(data.password):
                    user.password = await UserAuthManager.hash_password(data.password)
                else:
                    raise InvalidCredentialsException(
                        detail="The password does not meet the minimum security requirements."
                    )

            await self.db.commit()
            await self.db.refresh(user)

            logger.info(f"User updated their data: {user.email}")
            return user

        except (ResourceNotFoundException, InvalidCredentialsException, ResourceAlreadyExistsException):
            # Pass through already formatted exceptions
            await self.db.rollback()
            raise

        except Exception as e:
            await self.db.rollback()
            logger.exception(f"Error updating user: {str(e)}")
            raise DatabaseOperationException(
                detail="Error updating the user.",
                original_error=e
            )

    async def update_user(self, user_id: UUID, data: UserUpdate) -> User:
        """
        Allow an administrator to update any user.

        Args:
            user_id: User ID
            data: Data to be updated

        Returns:
            Updated user

        Raises:
            ResourceNotFoundException: If the user is not found
            ResourceInactiveException: If the user is inactive (except if being reactivated)
            ResourceAlreadyExistsException: If the new email is already in use
            DatabaseOperationException: If there's an error in the process
        """
        try:
            from sqlalchemy.future import select
            query = select(User).where(User.id == user_id)
            result = await self.db.execute(query)
            user = result.scalar_one_or_none()

            if not user:
                logger.warning(f"Attempt to update non-existent user: {user_id}")
                raise ResourceNotFoundException(
                    detail="User not found",
                    resource_id=user_id
                )

            # Check active status, EXCEPT if the update is reactivating the user
            is_reactivating = data.is_active is True and not user.is_active
            if not user.is_active and not is_reactivating:
                logger.warning(f"Attempt to update inactive user: {user_id}")
                raise ResourceInactiveException(
                    detail="This user is inactive. Use the reactivation operation first.",
                    resource_id=user_id
                )

            # Check if new email already exists
            if data.email and data.email != user.email:
                query = select(User).where(
                    User.email == data.email,
                    User.id != user_id
                )
                result = await self.db.execute(query)
                existing = result.scalar_one_or_none()

                if existing:
                    logger.warning(f"Email already in use when updating user: {data.email}")
                    raise ResourceAlreadyExistsException(
                        detail="This email is already in use."
                    )

                user.email = data.email

            if data.password is not None:
                # Verify password strength using domain service
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(data.password):
                    user.password = await UserAuthManager.hash_password(data.password)
                else:
                    raise InvalidCredentialsException(
                        detail="The password does not meet the minimum security requirements."
                    )

            if data.is_active is not None:
                user.is_active = data.is_active

            if data.is_superuser is not None:
                user.is_superuser = data.is_superuser

            await self.db.commit()
            await self.db.refresh(user)

            logger.info(f"Administrator updated user data: {user.id}")
            return user

        except (ResourceNotFoundException, ResourceAlreadyExistsException, ResourceInactiveException):
            # Pass through already formatted exceptions
            await self.db.rollback()
            raise

        except Exception as e:
            await self.db.rollback()
            logger.exception(f"Error updating user: {str(e)}")
            raise DatabaseOperationException(
                detail="Error updating the user.",
                original_error=e
            )

    async def deactivate_user(self, user_id: UUID) -> dict:
        """
        Deactivate a user (soft delete).

        Args:
            user_id: User ID

        Returns:
            Success message

        Raises:
            ResourceNotFoundException: If the user is not found
            DatabaseOperationException: If there's an error in the process
        """
        try:
            user = await self._get_user_by_id(user_id)

            if not user.is_active:
                return {"message": f"User '{user.email}' is already inactive."}

            user.is_active = False

            await self.db.commit()
            logger.info(f"User deactivated: {user.email}")
            return {"message": f"User '{user.email}' successfully deactivated."}

        except ResourceNotFoundException:
            # Pass through already formatted exception
            await self.db.rollback()
            raise

        except Exception as e:
            await self.db.rollback()
            logger.exception(f"Error deactivating user: {str(e)}")
            raise DatabaseOperationException(
                detail="Error deactivating the user.",
                original_error=e
            )

    async def reactivate_user(self, user_id: UUID) -> dict:
        """
        Reactivate a previously deactivated user.

        Args:
            user_id: User ID

        Returns:
            Success message

        Raises:
            ResourceNotFoundException: If the user is not found
            DatabaseOperationException: If there's an error in the process
        """
        try:
            # Here we need to directly fetch the user by ID without checking active status
            from sqlalchemy.future import select
            query = select(User).where(User.id == user_id)
            result = await self.db.execute(query)
            user = result.scalar_one_or_none()

            if not user:
                logger.warning(f"Attempt to reactivate non-existent user: {user_id}")
                raise ResourceNotFoundException(
                    detail="User not found",
                    resource_id=user_id
                )

            if user.is_active:
                return {"message": f"User '{user.email}' is already active."}

            user.is_active = True

            await self.db.commit()
            logger.info(f"User reactivated: {user.email}")
            return {"message": f"User '{user.email}' successfully reactivated."}

        except ResourceNotFoundException:
            # Pass through already formatted exception
            await self.db.rollback()
            raise

        except Exception as e:
            await self.db.rollback()
            logger.exception(f"Error reactivating user: {str(e)}")
            raise DatabaseOperationException(
                detail="Error reactivating the user.",
                original_error=e
            )

    async def delete_user_permanently(self, user_id: UUID) -> dict:
        """
        Permanently delete a user.

        Args:
            user_id: User ID

        Returns:
            Success message

        Raises:
            ResourceNotFoundException: If the user is not found.
            DatabaseOperationException: If there's an error in the process.
        """
        try:
            # Here we can use the method that checks if user exists
            user = await self._get_user_by_id(user_id)

            # Remove user from all groups and permissions
            user.groups = []
            user.permissions = []

            # Delete the user
            await self.db.delete(user)
            await self.db.commit()

            logger.info(f"User permanently deleted: {user.email}")
            return {"message": f"User '{user.email}' permanently deleted."}

        except ResourceNotFoundException:
            await self.db.rollback()
            raise

        except Exception as e:
            await self.db.rollback()
            logger.exception(f"Error permanently deleting user: {str(e)}")
            raise DatabaseOperationException(
                detail="Error permanently deleting the user.",
                original_error=e
            )
