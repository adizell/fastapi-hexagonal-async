# app/adapters/outbound/persistence/repositories/base_repository.py (async version)

from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union
from fastapi.encoders import jsonable_encoder
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.future import select
import logging

from app.adapters.outbound.persistence.models.base_model import Base
from app.domain.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    DatabaseOperationException
)

# Define generic type for SQLAlchemy models
ModelType = TypeVar("ModelType", bound=Base)
# Define generic types for Pydantic DTOs
CreateSchemaType = TypeVar("CreateSchemaType")
UpdateSchemaType = TypeVar("UpdateSchemaType")

# Configure logger
logger = logging.getLogger(__name__)


class AsyncCRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """
    Async base class for implementing the Repository pattern.

    Provides generic CRUD operations that can be used by any entity.
    Includes consistent error handling and logging.

    Attributes:
        model: SQLAlchemy model class
        logger: Configured logger for the class
    """

    def __init__(self, model: Type[ModelType]):
        """
        Initialize the repository with an SQLAlchemy model.

        Args:
            model: SQLAlchemy model class associated with this repository
        """
        self.model = model
        self.logger = logging.getLogger(f"{__name__}.{model.__name__}")

    async def get(self, db: AsyncSession, id: Any) -> Optional[ModelType]:
        """
        Get an entity by ID.

        Args:
            db: Async database session
            id: ID of the entity

        Returns:
            Entity found or None if it doesn't exist
        """
        try:
            query = select(self.model).where(self.model.id == id)
            result = await db.execute(query)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            self.logger.error(f"Error fetching {self.model.__name__} with ID {id}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error fetching {self.model.__name__}",
                original_error=e
            )

    async def get_by_field(self, db: AsyncSession, field_name: str, value: Any) -> Optional[ModelType]:
        """
        Get an entity by the value of a specific field.

        Args:
            db: Async database session
            field_name: Name of the field/column to filter
            value: Value to filter

        Returns:
            Entity found or None if it doesn't exist

        Raises:
            DatabaseOperationException: If an error occurs in the query
        """
        try:
            query = select(self.model).where(getattr(self.model, field_name) == value)
            result = await db.execute(query)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            self.logger.error(f"Error fetching {self.model.__name__} with {field_name}={value}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error fetching {self.model.__name__} by {field_name}",
                original_error=e
            )

    async def exists(self, db: AsyncSession, **filters) -> bool:
        """
        Check if an entity exists with the specified filters.

        Args:
            db: Async database session
            **filters: Filters in the format field=value

        Returns:
            True if it exists, False otherwise

        Raises:
            DatabaseOperationException: If an error occurs in the query
        """
        try:
            query = select(self.model)
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.where(getattr(self.model, field) == value)

            result = await db.execute(select(query.exists()))
            return result.scalar()
        except SQLAlchemyError as e:
            self.logger.error(f"Error checking existence of {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error checking existence of {self.model.__name__}",
                original_error=e
            )

    async def get_multi(
            self, db: AsyncSession, *, skip: int = 0, limit: int = 100, **filters
    ) -> List[ModelType]:
        """
        Get multiple entities with pagination and optional filters.

        Args:
            db: Async database session
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            **filters: Additional filters in the format field=value

        Returns:
            List of found entities

        Raises:
            DatabaseOperationException: If an error occurs in the query
        """
        try:
            query = select(self.model)

            # Apply dynamic filters
            for field, value in filters.items():
                if hasattr(self.model, field) and value is not None:
                    if isinstance(value, str) and value.startswith("%") and value.endswith("%"):
                        # LIKE filter for strings with wildcards
                        query = query.where(getattr(self.model, field).ilike(value))
                    else:
                        # Standard equality filter
                        query = query.where(getattr(self.model, field) == value)

            query = query.offset(skip).limit(limit)
            result = await db.execute(query)
            return result.scalars().all()
        except SQLAlchemyError as e:
            self.logger.error(f"Error listing {self.model.__name__}s: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error listing {self.model.__name__}s",
                original_error=e
            )

    async def create(self, db: AsyncSession, *, obj_in: CreateSchemaType) -> ModelType:
        """
        Create a new entity.

        Args:
            db: Async database session
            obj_in: Creation schema with entity data

        Returns:
            Newly created entity

        Raises:
            ResourceAlreadyExistsException: If the entity already exists
            DatabaseOperationException: If another database error occurs
        """
        try:
            # Convert Pydantic schema to dictionary
            obj_in_data = jsonable_encoder(obj_in)

            # Create model instance with data
            db_obj = self.model(**obj_in_data)

            # Add and persist in database
            db.add(db_obj)
            await db.commit()
            await db.refresh(db_obj)

            self.logger.info(f"{self.model.__name__} created with ID: {db_obj.id}")
            return db_obj

        except IntegrityError as e:
            await db.rollback()
            error_msg = str(e).lower()
            if 'unique' in error_msg or 'duplicate' in error_msg:
                self.logger.warning(f"Attempt to create duplicate {self.model.__name__}: {str(e)}")
                raise ResourceAlreadyExistsException(
                    detail=f"{self.model.__name__} with these data already exists"
                )
            else:
                self.logger.error(f"Integrity error creating {self.model.__name__}: {str(e)}")
                raise DatabaseOperationException(original_error=e)

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error creating {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error creating {self.model.__name__}",
                original_error=e
            )

    async def update(
            self, db: AsyncSession, *, db_obj: ModelType, obj_in: Union[UpdateSchemaType, Dict[str, Any]]
    ) -> ModelType:
        """
        Update an existing entity.

        Args:
            db: Async database session
            db_obj: Model instance to update
            obj_in: Update schema or dictionary with data to update

        Returns:
            Updated entity

        Raises:
            ResourceAlreadyExistsException: If the update violates a uniqueness constraint
            DatabaseOperationException: If another database error occurs
        """
        try:
            # Get current entity data
            obj_data = jsonable_encoder(db_obj)

            # Prepare update data
            if isinstance(obj_in, dict):
                update_data = obj_in
            else:
                update_data = obj_in.dict(exclude_unset=True)

            # Update each field with new values
            for field in obj_data:
                if field in update_data:
                    setattr(db_obj, field, update_data[field])

            # Save changes
            db.add(db_obj)
            await db.commit()
            await db.refresh(db_obj)

            self.logger.info(f"{self.model.__name__} with ID {db_obj.id} updated")
            return db_obj

        except IntegrityError as e:
            await db.rollback()
            error_msg = str(e).lower()
            if 'unique' in error_msg or 'duplicate' in error_msg:
                self.logger.warning(f"Uniqueness violation updating {self.model.__name__}: {str(e)}")
                raise ResourceAlreadyExistsException(
                    detail=f"Could not update {self.model.__name__}: value already exists"
                )
            else:
                self.logger.error(f"Integrity error updating {self.model.__name__}: {str(e)}")
                raise DatabaseOperationException(original_error=e)

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error updating {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error updating {self.model.__name__}",
                original_error=e
            )

    async def remove(self, db: AsyncSession, *, id: Any) -> ModelType:
        """
        Remove an entity by ID.

        Args:
            db: Async database session
            id: ID of the entity to remove

        Returns:
            Removed entity

        Raises:
            ResourceNotFoundException: If the entity doesn't exist
            DatabaseOperationException: If an error occurs during removal
        """
        try:
            # Find the entity
            obj = await self.get(db, id)
            if not obj:
                raise ResourceNotFoundException(
                    detail=f"{self.model.__name__} with ID {id} not found",
                    resource_id=id
                )

            # Remove the entity
            await db.delete(obj)
            await db.commit()

            self.logger.info(f"{self.model.__name__} with ID {id} removed")
            return obj

        except IntegrityError as e:
            await db.rollback()
            self.logger.error(f"Integrity error removing {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Cannot remove {self.model.__name__} as it is being used by other entities",
                original_error=e
            )

        except ResourceNotFoundException:
            # Pass through the already formatted exception
            await db.rollback()
            raise

        except SQLAlchemyError as e:
            await db.rollback()
            self.logger.error(f"Error removing {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error removing {self.model.__name__}",
                original_error=e
            )

    async def count(self, db: AsyncSession, **filters) -> int:
        """
        Count the number of entities matching the filters.

        Args:
            db: Async database session
            **filters: Filters in the format field=value

        Returns:
            Number of entities matching the filters

        Raises:
            DatabaseOperationException: If an error occurs in the query
        """
        try:
            query = select(self.model)

            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field) and value is not None:
                    query = query.where(getattr(self.model, field) == value)

            result = await db.execute(select(db.query(query.subquery()).count()))
            return result.scalar()

        except SQLAlchemyError as e:
            self.logger.error(f"Error counting {self.model.__name__}s: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Error counting {self.model.__name__}s",
                original_error=e
            )
