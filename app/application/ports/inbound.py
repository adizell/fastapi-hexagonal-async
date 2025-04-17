# app/application/ports/inbound.py

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from uuid import UUID

from app.application.dtos.user_dto import UserCreate, UserOutput, UserUpdate, TokenData
from app.application.dtos.client_dto import Client


class IUserUseCase(ABC):
    """Interface for user-related use cases."""

    @abstractmethod
    def register_user(self, user_data: UserCreate) -> UserOutput:
        """Register a new user."""
        pass

    @abstractmethod
    def authenticate_user(self, email: str, password: str) -> TokenData:
        """Authenticate a user and return access token."""
        pass

    @abstractmethod
    def update_user(self, user_id: UUID, data: UserUpdate) -> UserOutput:
        """Update user data."""
        pass

    @abstractmethod
    def deactivate_user(self, user_id: UUID) -> Dict[str, str]:
        """Deactivate a user (soft delete)."""
        pass

    @abstractmethod
    def reactivate_user(self, user_id: UUID) -> Dict[str, str]:
        """Reactivate a previously deactivated user."""
        pass

    @abstractmethod
    def get_user_by_id(self, user_id: UUID) -> UserOutput:
        """Get user by ID."""
        pass

    @abstractmethod
    def get_user_by_email(self, email: str) -> UserOutput:
        """Get user by email."""
        pass


class IClientUseCase(ABC):
    """Interface for client-related use cases."""

    @abstractmethod
    def create_client(self) -> Dict[str, str]:
        """Create a new client with generated credentials."""
        pass

    @abstractmethod
    def authenticate_client(self, client_id: str, client_secret: str) -> str:
        """Authenticate client and return access token."""
        pass

    @abstractmethod
    def update_client_secret(self, client_id: str) -> Dict[str, str]:
        """Update a client's secret key."""
        pass
