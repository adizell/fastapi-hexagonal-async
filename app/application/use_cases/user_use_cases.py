# app/application/use_cases/user_use_cases.py

"""
Serviço para gerenciamento de usuários.

Este módulo implementa o serviço para operações com usuários,
incluindo registro, autenticação, atualização e gerenciamento de perfis.
"""

from uuid import UUID
from datetime import datetime, timedelta
import logging
from sqlalchemy.orm import Session
from fastapi_pagination import Params
from fastapi_pagination.ext.sqlalchemy import paginate as sqlalchemy_paginate

from app.adapters.outbound.persistence.models import User
from app.adapters.outbound.persistence.models import AuthGroup
from app.application.dtos.user_dto import UserCreate, UserUpdate, UserSelfUpdate, TokenData
from app.adapters.outbound.security.auth_user_manager import UserAuthManager
from app.domain.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    InvalidCredentialsException,
    DatabaseOperationException,
    PermissionDeniedException,
    ResourceInactiveException
)
from app.domain.services.user_service import UserPermissionService

# Configurar logger
logger = logging.getLogger(__name__)


class UserService:
    """
    Serviço para gerenciamento de usuários.

    Esta classe implementa a lógica de negócios relacionada à
    manipulação de usuários, incluindo autenticação, autorização e gerenciamento.
    """

    def __init__(self, db_session: Session):
        """
        Inicializa o serviço com uma sessão de banco de dados.

        Args:
            db_session: Sessão SQLAlchemy ativa
        """
        self.db = db_session

    def _get_user_by_id(self, user_id: UUID) -> User:
        """
        Obtém um usuário pelo ID ou lança uma exceção se não existir.

        Args:
            user_id: UUID do usuário

        Returns:
            Objeto User

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            ResourceInactiveException: Se o usuário estiver inativo
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.warning(f"Usuário não encontrado: ID {user_id}")
            raise ResourceNotFoundException(
                detail="Usuário não encontrado",
                resource_id=user_id
            )

        # Adicionar verificação de status ativo
        if not user.is_active:
            logger.warning(f"Tentativa de acessar usuário inativo: ID {user_id}")
            raise ResourceInactiveException(
                detail="Este usuário está inativo e não está disponível",
                resource_id=user_id
            )

        return user

    def _get_user_by_email(self, email: str) -> User:
        """
        Obtém um usuário pelo email ou lança uma exceção se não existir.

        Args:
            email: Email do usuário

        Returns:
            Objeto User

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            ResourceInactiveException: Se o usuário estiver inativo
        """
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"Usuário não encontrado: email {email}")
            raise ResourceNotFoundException(
                detail="Usuário não encontrado com este email"
            )

        # Verificação de status ativo
        if not user.is_active:
            logger.warning(f"Tentativa de acessar usuário inativo: email {email}")
            raise ResourceInactiveException(
                detail="Este usuário está inativo e não está disponível"
            )

        return user

    def _get_group_by_name(self, name: str) -> AuthGroup:
        """
        Retorna o grupo de permissões pelo nome.

        Args:
            name: Nome do grupo

        Returns:
            Objeto AuthGroup

        Raises:
            DatabaseOperationException: Se o grupo não for encontrado
        """
        group = self.db.query(AuthGroup).filter(AuthGroup.name == name).first()
        if not group:
            error_msg = f"Grupo '{name}' não encontrado. Verifique a carga inicial (seed)."
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg)
        return group

    def list_users(self, current_user: User, params: Params, order: str = "desc"):
        """
        Lista paginada de usuários ordenados por data de criação.

        Args:
            current_user: Usuário autenticado
            params: Parâmetros de paginação
            order: Direção de ordenação (asc|desc)

        Returns:
            Lista paginada de usuários

        Raises:
            PermissionDeniedException: Se o usuário não for superusuário
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            # Verificar permissão usando domínio service
            if not current_user.is_superuser:
                logger.warning(f"Usuário sem permissão tentou listar todos os usuários: {current_user.email}")
                raise PermissionDeniedException(
                    detail="Apenas superusuários podem listar todos os usuários."
                )

            query = self.db.query(User)
            query = query.order_by(User.created_at.desc() if order == "desc" else User.created_at.asc())

            logger.info(f"Listagem de usuários realizada por: {current_user.email}")
            return sqlalchemy_paginate(query, params)

        except PermissionDeniedException:
            # Repassa exceção já formatada
            raise

        except Exception as e:
            logger.exception(f"Erro ao listar usuários: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao listar usuários",
                original_error=e
            )

    def update_self(self, user_id: UUID, data: UserSelfUpdate) -> User:
        """
        Permite que um usuário atualize seu próprio perfil.

        Args:
            user_id: ID do usuário
            data: Dados a serem atualizados

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            ResourceInactiveException: Se o usuário estiver inativo
            InvalidCredentialsException: Se a senha atual for incorreta
            ResourceAlreadyExistsException: Se o novo email já estiver em uso
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            # Usar o método que já verifica o status ativo
            user = self._get_user_by_id(user_id)

            # Se tentar alterar senha, verificar senha atual
            if data.password and not data.current_password:
                logger.warning(f"Tentativa de alterar senha sem fornecer senha atual: {user.email}")
                raise InvalidCredentialsException(
                    detail="Para alterar a senha, é necessário fornecer a senha atual."
                )

            # Verificar senha atual se for fornecida
            if data.current_password:
                if not UserAuthManager.verify_password(data.current_password, user.password):
                    logger.warning(f"Senha atual incorreta ao atualizar usuário: {user.email}")
                    raise InvalidCredentialsException(
                        detail="Senha atual incorreta."
                    )

            # Atualizar campos
            if data.email is not None and data.email != user.email:
                # Verificar se novo email já existe
                existing = self.db.query(User).filter(
                    User.email == data.email,
                    User.id != user_id
                ).first()

                if existing:
                    logger.warning(f"Email já em uso ao atualizar usuário: {data.email}")
                    raise ResourceAlreadyExistsException(
                        detail="Este email já está em uso."
                    )

                user.email = data.email

            if data.password is not None:
                # Verificar força da senha usando domain service antes de definir
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(data.password):
                    user.password = UserAuthManager.hash_password(data.password)
                else:
                    raise InvalidCredentialsException(
                        detail="A senha não atende aos requisitos mínimos de segurança."
                    )

            self.db.commit()
            self.db.refresh(user)

            logger.info(f"Usuário atualizou seus dados: {user.email}")
            return user

        except (ResourceNotFoundException, InvalidCredentialsException, ResourceAlreadyExistsException):
            # Repassa exceções já formatadas
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            logger.exception(f"Erro ao atualizar usuário: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar o usuário.",
                original_error=e
            )

    def update_user(self, user_id: UUID, data: UserUpdate) -> User:
        """
        Permite que um administrador atualize qualquer usuário.

        Args:
            user_id: ID do usuário
            data: Dados a serem atualizados

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            ResourceInactiveException: Se o usuário estiver inativo (exceto se estiver sendo reativado)
            ResourceAlreadyExistsException: Se o novo email já estiver em uso
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            user = self.db.query(User).filter(User.id == user_id).first()

            if not user:
                logger.warning(f"Tentativa de atualizar usuário inexistente: {user_id}")
                raise ResourceNotFoundException(
                    detail="Usuário não encontrado",
                    resource_id=user_id
                )

            # Verificar status ativo, EXCETO se a atualização está reativando o usuário
            is_reactivating = data.is_active is True and not user.is_active
            if not user.is_active and not is_reactivating:
                logger.warning(f"Tentativa de atualizar usuário inativo: {user_id}")
                raise ResourceInactiveException(
                    detail="Este usuário está inativo. Use a operação de reativação primeiro.",
                    resource_id=user_id
                )

            # Verificar se novo email já existe
            if data.email and data.email != user.email:
                existing = self.db.query(User).filter(
                    User.email == data.email,
                    User.id != user_id
                ).first()

                if existing:
                    logger.warning(f"Email já em uso ao atualizar usuário: {data.email}")
                    raise ResourceAlreadyExistsException(
                        detail="Este email já está em uso."
                    )

                user.email = data.email

            if data.password is not None:
                # Verificar força da senha usando domain service antes de definir
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(data.password):
                    user.password = UserAuthManager.hash_password(data.password)
                else:
                    raise InvalidCredentialsException(
                        detail="A senha não atende aos requisitos mínimos de segurança."
                    )

            if data.is_active is not None:
                user.is_active = data.is_active

            if data.is_superuser is not None:
                user.is_superuser = data.is_superuser

            self.db.commit()
            self.db.refresh(user)

            logger.info(f"Administrador atualizou dados do usuário: {user.id}")
            return user

        except (ResourceNotFoundException, ResourceAlreadyExistsException, ResourceInactiveException):
            # Repassa exceções já formatadas
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            logger.exception(f"Erro ao atualizar usuário: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar o usuário.",
                original_error=e
            )

    def deactivate_user(self, user_id: UUID) -> dict:
        """
        Desativa um usuário (soft delete).

        Args:
            user_id: ID do usuário

        Returns:
            Mensagem de sucesso

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            user = self._get_user_by_id(user_id)

            if not user.is_active:
                return {"message": f"Usuário '{user.email}' já está inativo."}

            user.is_active = False

            self.db.commit()
            logger.info(f"Usuário desativado: {user.email}")
            return {"message": f"Usuário '{user.email}' desativado com sucesso."}

        except ResourceNotFoundException:
            # Repassa exceção já formatada
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            logger.exception(f"Erro ao desativar usuário: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao desativar o usuário.",
                original_error=e
            )

    def reactivate_user(self, user_id: UUID) -> dict:
        """
        Reativa um usuário previamente desativado.

        Args:
            user_id: ID do usuário

        Returns:
            Mensagem de sucesso

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            DatabaseOperationException: Se houver erro no processo
        """
        try:
            # Aqui precisamos diretamente buscar o usuário pelo ID sem verificar o status ativo
            user = self.db.query(User).filter(User.id == user_id).first()

            if not user:
                logger.warning(f"Tentativa de reativar usuário inexistente: {user_id}")
                raise ResourceNotFoundException(
                    detail="Usuário não encontrado",
                    resource_id=user_id
                )

            if user.is_active:
                return {"message": f"Usuário '{user.email}' já está ativo."}

            user.is_active = True

            self.db.commit()
            logger.info(f"Usuário reativado: {user.email}")
            return {"message": f"Usuário '{user.email}' reativado com sucesso."}

        except ResourceNotFoundException:
            # Repassa exceção já formatada
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            logger.exception(f"Erro ao reativar usuário: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao reativar o usuário.",
                original_error=e
            )

    def delete_user_permanently(self, user_id: UUID) -> dict:
        """
        Exclui permanentemente um usuário.

        Args:
            user_id: ID do usuário

        Returns:
            dict: Mensagem de sucesso

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado.
            DatabaseOperationException: Se houver erro no processo.
        """
        try:
            # Aqui podemos utilizar o método já existente que verifica se o usuário existe
            user = self._get_user_by_id(user_id)

            # Remover usuário de todos os grupos e permissões
            user.groups = []
            user.permissions = []

            # Deletar o usuário
            self.db.delete(user)
            self.db.commit()

            logger.info(f"Usuário excluído permanentemente: {user.email}")
            return {"message": f"Usuário '{user.email}' excluído permanentemente."}

        except ResourceNotFoundException:
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            logger.exception(f"Erro ao excluir usuário permanentemente: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao excluir o usuário permanentemente.",
                original_error=e
            )
