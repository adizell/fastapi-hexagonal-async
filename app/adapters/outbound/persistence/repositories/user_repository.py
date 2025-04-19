# app/adapters/outbound/persistence/repositories/user_repository.py (async version)

"""
Repository for user operations.

This module implements the repository that performs database operations
related to users, implementing the IUserRepository interface.
"""

from typing import Optional, List, Dict, Any, Union
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from fastapi.encoders import jsonable_encoder

from app.adapters.outbound.persistence.repositories.base_repository import AsyncCRUDBase
from app.adapters.outbound.persistence.models import User, AuthGroup
from app.application.dtos.user_dto import UserCreate, UserUpdate
from app.application.ports.outbound import IUserRepository
from app.domain.models.user_domain_model import User as DomainUser
from app.domain.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    DatabaseOperationException,
    InvalidCredentialsException
)


class AsyncUserCRUD(AsyncCRUDBase[User, UserCreate, UserUpdate], IUserRepository):
    """
    Async implementation of CRUD repository for the User entity.

    Extends AsyncCRUDBase with user-specific operations,
    such as email lookup and credential verification.
    """

    async def get_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """
        Find a user by email.

        Args:
            db: Async database session
            email: User's email

        Returns:
            User found or None if doesn't exist

        Raises:
            DatabaseOperationException: In case of database error
        """
        try:
            query = select(User).where(User.email == email)
            result = await db.execute(query)
            return result.unique().scalar_one_or_none()
        except SQLAlchemyError as e:
            self.logger.error(f"Error fetching user by email '{email}': {e}")
            raise DatabaseOperationException(
                detail="Error fetching user by email",
                original_error=e
            )

    async def create_with_password(self, db: AsyncSession, *, obj_in: UserCreate) -> User:
        """
        Create a new user with secure password.

        Args:
            db: Async database session
            obj_in: User data to create

        Returns:
            New User created

        Raises:
            ResourceAlreadyExistsException: If the email is already in use
            DatabaseOperationException: In case of database error
        """
        # Import password manager here to avoid import cycle
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Check if email already exists
            existing_user = await self.get_by_email(db, email=obj_in.email)
            if existing_user:
                self.logger.warning(f"Attempt to create user with existing email: {obj_in.email}")
                raise ResourceAlreadyExistsException(
                    detail=f"User with email '{obj_in.email}' already exists"
                )

            # Verify password strength using domain service
            from app.domain.services.auth_service import PasswordService
            if not PasswordService.verify_password_strength(obj_in.password):
                raise InvalidCredentialsException(
                    detail="Password does not meet minimum security requirements."
                )

            # Convert schema to dict and extract password
            obj_in_data = jsonable_encoder(obj_in)
            password = obj_in_data.pop("password")

            # Create model instance and assign password hash
            db_obj = User(**obj_in_data)
            db_obj.password = await UserAuthManager.hash_password(password)

            # Add to default 'user' group
            query = select(AuthGroup).where(AuthGroup.name == "user")
            result = await db.execute(query)
            user_group = result.scalar_one_or_none()

            if user_group:
                db_obj.groups.append(user_group)

            # Persist to database
            db.add(db_obj)
            await db.commit()
            await db.refresh(db_obj)
            self.logger.info(f"User created with email: {db_obj.email}")
            return db_obj

        except ResourceAlreadyExistsException:
            # Pass through duplicity exception
            await db.rollback()
            raise
        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error creating user: {e}")
            raise DatabaseOperationException(
                detail="Error creating user",
                original_error=e
            )

    async def update_with_password(
            self,
            db: AsyncSession,
            *,
            db_obj: User,
            obj_in: Union[UserUpdate, Dict[str, Any]]
    ) -> User:
        """
        Update a user, optionally including password.

        Args:
            db: Async database session
            db_obj: User object to update
            obj_in: Update data

        Returns:
            Updated User

        Raises:
            ResourceAlreadyExistsException: If the new email is already in use
            DatabaseOperationException: In case of database error
        """
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Convert update data to dict
            update_data = (
                obj_in if isinstance(obj_in, dict) else obj_in.dict(exclude_unset=True)
            )

            # Check for email conflict
            if "email" in update_data and update_data["email"] != db_obj.email:
                existing = await self.get_by_email(db, email=update_data["email"])
                if existing and existing.id != db_obj.id:
                    raise ResourceAlreadyExistsException(
                        detail=f"Email '{update_data['email']}' is already in use"
                    )

            # Process password
            if "password" in update_data and update_data["password"]:
                # Verify password strength using domain service
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(update_data["password"]):
                    update_data["password"] = await UserAuthManager.hash_password(update_data["password"])
                else:
                    raise InvalidCredentialsException(
                        detail="Password does not meet minimum security requirements."
                    )
            elif "password" in update_data:
                # Remove empty password
                del update_data["password"]

            # Use generic method for update
            return await super().update(db, db_obj=db_obj, obj_in=update_data)

        except ResourceAlreadyExistsException:
            # Pass through the exception
            await db.rollback()
            raise
        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error updating user: {e}")
            raise DatabaseOperationException(
                detail="Error updating user",
                original_error=e
            )

    async def authenticate(self, db: AsyncSession, *, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user by verifying email and password.

        Args:
            db: Async database session
            email: User's email
            password: Plain text password

        Returns:
            Authenticated User or None

        Raises:
            InvalidCredentialsException: If credentials are invalid
            DatabaseOperationException: In case of database error
        """
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Find user by email
            user = await self.get_by_email(db, email=email)
            if not user:
                self.logger.warning(f"Login attempt with non-existent email: {email}")
                raise InvalidCredentialsException(detail="Incorrect email or password")

            # Check if user is active
            if not user.is_active:
                self.logger.warning(f"Login attempt with inactive user: {email}")
                raise InvalidCredentialsException(detail="Inactive user")

            # Verify password
            if not await UserAuthManager.verify_password(password, user.password):
                self.logger.warning(f"Login attempt with incorrect password: {email}")
                raise InvalidCredentialsException(detail="Incorrect email or password")

            return user

        except InvalidCredentialsException:
            # Pass through the exception
            raise
        except SQLAlchemyError as e:
            self.logger.error(f"Error authenticating user: {e}")
            raise DatabaseOperationException(
                detail="Error authenticating user",
                original_error=e
            )

    async def activate_deactivate(self, db: AsyncSession, *, user_id: UUID, is_active: bool) -> User:
        """
        Activate or deactivate a user.

        Args:
            db: Async database session
            user_id: User ID
            is_active: New status (True for active, False for inactive)

        Returns:
            Updated user

        Raises:
            ResourceNotFoundException: If the user is not found
            DatabaseOperationException: In case of database error
        """
        try:
            # Find user
            user = await self.get(db, id=user_id)
            if not user:
                raise ResourceNotFoundException(
                    detail=f"User with ID {user_id} not found",
                    resource_id=user_id
                )

            # Update status
            user.is_active = is_active

            # Save changes
            db.add(user)
            await db.commit()
            await db.refresh(user)

            status_text = "activated" if is_active else "deactivated"
            self.logger.info(f"User {user.id} {status_text}")
            return user

        except ResourceNotFoundException:
            # Pass through the exception
            await db.rollback()
            raise

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error changing user status: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error {'activating' if is_active else 'deactivating'} user",
                original_error=e
            )

    async def get_users_with_permissions(
            self,
            db: AsyncSession,
            *,
            skip: int = 0,
            limit: int = 100,
            include_inactive: bool = False
    ) -> List[User]:
        """
        List users with their groups and permissions loaded.

        Args:
            db: Async database session
            skip: Records to skip
            limit: Maximum records to return
            include_inactive: Whether to include inactive users

        Returns:
            List of users with groups and permissions

        Raises:
            DatabaseOperationException: In case of database error
        """
        try:
            from sqlalchemy.orm import selectinload

            query = select(User)

            # Filter active/inactive users
            if not include_inactive:
                query = query.where(User.is_active == True)

            # Load relationships eagerly (groups and permissions)
            query = query.options(
                selectinload(User.groups).selectinload(AuthGroup.permissions),
                selectinload(User.permissions)
            )

            # Apply pagination
            query = query.offset(skip).limit(limit)

            result = await db.execute(query)
            return result.scalars().all()

        except SQLAlchemyError as e:
            self.logger.error(f"Error listing users with permissions: {str(e)}")
            raise DatabaseOperationException(
                detail="Error listing users with permissions",
                original_error=e
            )

    def to_domain(self, db_model: User) -> DomainUser:
        """
        Convert database model to domain model.

        Args:
            db_model: User ORM model

        Returns:
            Domain model of user
        """
        from app.domain.models.user_domain_model import Group, Permission

        # Convert groups
        groups = []
        for group_model in db_model.groups:
            # Convert group permissions
            permissions = []
            for perm_model in group_model.permissions:
                permission = Permission(
                    id=perm_model.id,
                    name=perm_model.name,
                    codename=perm_model.codename,
                    content_type_id=perm_model.content_type_id
                )
                permissions.append(permission)

            group = Group(
                id=group_model.id,
                name=group_model.name,
                permissions=permissions
            )
            groups.append(group)

        # Convert direct permissions
        permissions = []
        for perm_model in db_model.permissions:
            permission = Permission(
                id=perm_model.id,
                name=perm_model.name,
                codename=perm_model.codename,
                content_type_id=perm_model.content_type_id
            )
            permissions.append(permission)

        # Create domain model
        return DomainUser(
            id=db_model.id,
            email=db_model.email,
            password=db_model.password,
            is_active=db_model.is_active,
            is_superuser=db_model.is_superuser,
            created_at=db_model.created_at,
            updated_at=db_model.updated_at,
            groups=groups,
            permissions=permissions
        )

    async def delete(self, db: AsyncSession, *, id: Any) -> None:
        """
        Delete a user by ID.

        Args:
            db: Async database session
            id: ID of the user to delete

        Raises:
            ResourceNotFoundException: If the user is not found
        """
        user = await self.get(db, id=id)
        if not user:
            raise ResourceNotFoundException(
                detail=f"User with ID {id} not found",
                resource_id=id
            )

        await db.delete(user)
        await db.commit()
        return user

    async def list(self, db: AsyncSession, *, skip: int = 0, limit: int = 100, **filters) -> List[User]:
        """
        List users with optional filtering.

        Args:
            db: Async database session
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            **filters: Additional filters

        Returns:
            List of User objects
        """
        return await self.get_multi(db, skip=skip, limit=limit, **filters)


# Public instance to be used by use cases
user_repository = AsyncUserCRUD(User)
