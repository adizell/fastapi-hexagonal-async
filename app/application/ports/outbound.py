# app/application/ports/outbound.py

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any, Generic, TypeVar
from uuid import UUID

from app.domain.models.user_domain_model import User
from app.domain.models.client_domain_model import Client

T = TypeVar('T')


class IRepository(Generic[T], ABC):
    """Generic repository interface."""

    @abstractmethod
    def get(self, id: Any) -> Optional[T]:
        """Get entity by ID."""
        pass

    @abstractmethod
    def list(self, skip: int = 0, limit: int = 100, **filters) -> List[T]:
        """List entities with optional filters."""
        pass

    @abstractmethod
    def create(self, entity: T) -> T:
        """Create a new entity."""
        pass

    @abstractmethod
    def update(self, entity: T) -> T:
        """Update an existing entity."""
        pass

    @abstractmethod
    def delete(self, id: Any) -> None:
        """Delete an entity by ID."""
        pass


class IUserRepository(IRepository[User], ABC):
    """User repository interface."""

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        pass

    @abstractmethod
    def create_with_password(self, user_data: Dict[str, Any]) -> User:
        """Create user with hashed password."""
        pass

    @abstractmethod
    def update_with_password(self, user: User, user_data: Dict[str, Any]) -> User:
        """Update user with optional password change."""
        pass


class IClientRepository(IRepository[Client], ABC):
    """Client repository interface."""

    @abstractmethod
    def get_by_client_id(self, client_id: str) -> Optional[Client]:
        """Get client by client_id."""
        pass

    @abstractmethod
    def create_with_credentials(self) -> Dict[str, str]:
        """Create client with generated credentials."""
        pass

    @abstractmethod
    def update_secret(self, client_id: str) -> Dict[str, str]:
        """Update client secret."""
        pass


class ITokenService(ABC):
    """Token handling interface."""

    @abstractmethod
    def create_access_token(self, subject: str, expires_delta: Optional[int] = None) -> str:
        """Create an access token."""
        pass

    @abstractmethod
    def create_refresh_token(self, subject: str, expires_delta: Optional[int] = None) -> str:
        """Create a refresh token."""
        pass

    @abstractmethod
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a token."""
        pass

    @abstractmethod
    def revoke_token(self, token_id: str, expires_at: datetime) -> None:
        """Revoke a token by adding to blacklist."""
        pass
