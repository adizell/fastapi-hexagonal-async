# app/adapters/outbound/security/permissions.py (async version)

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends, HTTPException, status

from app.adapters.inbound.api.deps import get_session, get_current_user
from app.adapters.outbound.persistence.models.user_model import User


async def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """
    Validates if the authenticated user is a superuser.
    Raises HTTP 403 if not.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access allowed only for superusers."
        )
    return current_user


def require_permission(permission_codename: str):
    """
    Returns a dependency that validates if the authenticated user has a specific permission.
    Superusers are automatically authorized.

    Usage:
        @router.get(..., dependencies=[Depends(require_permission("add_pet"))])
    """

    async def permission_checker(
            current_user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_session),
    ) -> User:
        if current_user.is_superuser:
            return current_user

        # Collect all user permissions
        user_permissions = {perm.codename for perm in current_user.permissions}
        for group in current_user.groups:
            for perm in group.permissions:
                user_permissions.add(perm.codename)

        if permission_codename not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission_codename}' denied to user."
            )

        return current_user

    return permission_checker


def require_permission_or_superuser(permission_codename: str):
    """
    Dependency that validates if the user has permission or is a superuser.
    """

    async def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser:
            return current_user

        user_permissions = {perm.codename for perm in current_user.permissions}
        for group in current_user.groups:
            user_permissions.update(perm.codename for perm in group.permissions)

        if permission_codename not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission_codename}' denied."
            )

        return current_user

    return checker
