# app/adapters/inbound/api/v1/endpoints/user_endpoint.py

import logging
from uuid import UUID
from fastapi_pagination import Params, Page
from fastapi import APIRouter, Depends, status, Query, HTTPException, Path
from sqlalchemy.orm import Session

from app.application.use_cases.user_use_cases import UserService
from app.adapters.outbound.persistence.models.user_model import User
from app.shared.utils.pagination import pagination_params
from app.adapters.outbound.security.permissions import require_superuser
from app.adapters.inbound.api.deps import (
    get_session,
    get_current_user,
    get_db_session
)
from app.domain.exceptions import (
    ResourceInactiveException,
    ResourceNotFoundException
)
from app.application.dtos.user_dto import (
    UserOutput,
    UserUpdate,
    UserListOutput,
    UserSelfUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/me",
    response_model=UserOutput,
    summary="Get My Data - Dados do usuário logado",
    description="Retorna os dados do usuário autenticado via token JWT.",
)
def get_my_data(
        db: Session = Depends(get_session),
        current_user: User = Depends(get_current_user),
):
    # Verificação adicional do status ativo
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Esta conta de usuário está inativa.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return current_user


@router.put(
    "/me",
    response_model=UserOutput,
    summary="Update My Data - Atualizar dados do próprio usuário",
    description="Permite que o usuário autenticado atualize seu próprio email e senha.",
)
def update_my_data(
        update_data: UserSelfUpdate,
        db: Session = Depends(get_session),
        current_user: User = Depends(get_current_user),
):
    """
    Permite que o usuário atualize seus próprios dados (email e password).
    Não permite que o usuário altere seu status ativo/inativo ou permissões.
    """
    return UserService(db).update_self(user_id=current_user.id, data=update_data)


@router.get(
    "/list",
    response_model=Page[UserListOutput],
    summary="List Users - Listar todos usuários",
    description="Retorna uma lista paginada de usuários. Apenas superusuários têm acesso.",
)
def list_users(
        db: Session = Depends(get_db_session),
        current_user: User = Depends(require_superuser),  # Garante que é superusuário
        params: Params = Depends(pagination_params),
        order: str = Query("desc", enum=["asc", "desc"], description="Ordenação por data de criação (asc ou desc)"),
):
    return UserService(db).list_users(current_user=current_user, params=params, order=order)


@router.put(
    "/update/{user_id}",
    response_model=UserOutput,
    summary="Update User - Atualizar dados de um usuário específico",
    description="Atualiza os dados de um usuário específico. Apenas superusuários têm acesso.",
)
def update_user(
        user_id: UUID = Path(..., description="ID do usuário a ser atualizado"),
        update_data: UserUpdate = ...,
        db: Session = Depends(get_session),
        current_user: User = Depends(require_superuser),  # Garante que é superusuário
):
    """
    Permite que um superusuário atualize os dados de qualquer usuário.
    """
    try:
        return UserService(db).update_user(user_id=user_id, data=update_data)
    except ResourceNotFoundException:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado."
        )
    except ResourceInactiveException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O usuário está inativo. Considere reativá-lo através do endpoint de reativação."
        )
    except Exception as e:
        logger.exception(f"Erro ao atualizar usuário: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro interno ao atualizar usuário: {str(e)}"
        )


@router.delete(
    "/deactivate/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Deactivate User - Desativar um usuário",
    description="Desativa (soft delete) um usuário específico. Apenas superusuários têm acesso.",
    response_model=dict,
)
def deactivate_user(
        user_id: UUID = Path(..., description="ID do usuário a ser desativado"),
        db: Session = Depends(get_session),
        current_user: User = Depends(require_superuser),  # Garante que é superusuário
):
    """
    Realiza soft delete do usuário, marcando-o como inativo.
    Usuários inativos não podem fazer login nem acessar recursos da API.
    """
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível desativar seu próprio usuário."
        )

    return UserService(db).deactivate_user(user_id=user_id)


@router.post(
    "/reactivate/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Reactivate User - Reativar um usuário",
    description="Reativa um usuário previamente desativado. Apenas superusuários têm acesso.",
    response_model=dict,
)
def reactivate_user(
        user_id: UUID = Path(..., description="ID do usuário a ser reativado"),
        db: Session = Depends(get_session),
        current_user: User = Depends(require_superuser),  # Garante que é superusuário
):
    """
    Reativa um usuário que estava inativo, permitindo que ele faça login novamente.
    """
    return UserService(db).reactivate_user(user_id=user_id)


@router.delete(
    "/delete/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete User Permanently - Excluir usuário permanentemente",
    description="Exclui permanentemente um usuário do sistema. Disponível apenas para administradores.",
    response_model=dict,
)
def delete_user_permanently(
        user_id: UUID = Path(..., description="ID do usuário a ser excluído"),
        db: Session = Depends(get_session),
        current_user: User = Depends(require_superuser),  # Garante que é superusuário
        confirm: bool = Query(False, description="Confirmação explícita para exclusão permanente"),
):
    """
    Exclui permanentemente um usuário do sistema.
    Esta operação não pode ser desfeita e requer confirmação explícita.
    Não será permitido excluir usuários que possuem pets vinculados.
    """
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível excluir seu próprio usuário."
        )

    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A exclusão permanente requer confirmação explícita. Adicione ?confirm=true à URL."
        )

    return UserService(db).delete_user_permanently(user_id=user_id)
