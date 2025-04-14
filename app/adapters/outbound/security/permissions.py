# app/adapters/outbound/security/permissions.py

from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status

from app.adapters.inbound.api.deps import get_session, get_current_user
from app.db.models.user import User


def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """
    Valida se o usuário autenticado é superusuário.
    Lánça HTTP 403 se não for.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso permitido apenas a superusuários."
        )
    return current_user


def require_permission(permission_codename: str):
    """
    Retorna uma dependência que valida se o usuário autenticado possui uma permissão específica.
    Superusuários são automaticamente autorizados.

    Uso:
        @router.get(..., dependencies=[Depends(require_permission("add_pet"))])
    """

    def permission_checker(
            current_user: User = Depends(get_current_user),
            db: Session = Depends(get_session),
    ) -> User:
        if current_user.is_superuser:
            return current_user

        # Coleta todas as permissões do usuário
        user_permissions = {perm.codename for perm in current_user.permissions}
        for group in current_user.groups:
            for perm in group.permissions:
                user_permissions.add(perm.codename)

        if permission_codename not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão '{permission_codename}' negada ao usuário."
            )

        return current_user

    return permission_checker


def require_permission_or_superuser(permission_codename: str):
    """
    Dependência que valida se o usuário tem permissão ou é superusuário.
    """

    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser:
            return current_user

        user_permissions = {perm.codename for perm in current_user.permissions}
        for group in current_user.groups:
            user_permissions.update(perm.codename for perm in group.permissions)

        if permission_codename not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão '{permission_codename}' negada."
            )

        return current_user

    return checker
