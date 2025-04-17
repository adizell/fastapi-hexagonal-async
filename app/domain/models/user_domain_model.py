# app/domain/models/user_domain_model.py

from uuid import UUID
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime


@dataclass
class User:
    """Domain model for a user entity."""
    id: UUID
    email: str
    password: str  # This would be hashed already
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    # Relationship collections would be represented as lists
    groups: List["Group"] = None
    permissions: List["Permission"] = None

    def __post_init__(self):
        # Initialize empty collections
        if self.groups is None:
            self.groups = []
        if self.permissions is None:
            self.permissions = []

    def has_permission(self, permission_code: str) -> bool:
        """Check if user has a specific permission directly or via groups."""
        # Superusers have all permissions
        if self.is_superuser:
            return True

        # Check direct permissions
        if any(p.codename == permission_code for p in self.permissions):
            return True

        # Check permissions via groups
        for group in self.groups:
            if any(p.codename == permission_code for p in group.permissions):
                return True

        return False


@dataclass
class Group:
    """Domain model for a permission group."""
    id: int
    name: str
    permissions: List["Permission"] = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []

    def has_permission(self, permission_code: str) -> bool:
        """Check if the group has a specific permission."""
        return any(p.codename == permission_code for p in self.permissions)


@dataclass
class Permission:
    """Domain model for a permission."""
    id: int
    name: str
    codename: str
    content_type_id: int
