# app/domain/services/user_service.py

from typing import List, Optional
from uuid import UUID

from app.domain.models.user_domain_model import User, Group, Permission


class UserPermissionService:
    """
    Domain service for user permission management.
    """

    @staticmethod
    def get_all_user_permissions(user: User) -> List[str]:
        """
        Get all permission codenames for a user.

        Args:
            user: The user to get permissions for

        Returns:
            List of permission codenames
        """
        if user.is_superuser:
            return ["*"]  # Superuser has all permissions

        # Collect direct permissions
        permissions = [p.codename for p in user.permissions]

        # Add permissions from groups
        for group in user.groups:
            for permission in group.permissions:
                if permission.codename not in permissions:
                    permissions.append(permission.codename)

        return permissions

    @staticmethod
    def check_permission(user: User, required_permission: str) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user: The user to check
            required_permission: The permission codename to check

        Returns:
            True if the user has the permission
        """
        # Superusers have all permissions
        if user.is_superuser:
            return True

        return user.has_permission(required_permission)
