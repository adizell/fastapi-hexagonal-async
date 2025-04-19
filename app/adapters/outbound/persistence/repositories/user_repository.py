# app/adapters/outbound/persistence/repositories/user_repository.py

"""
Repositório para operações com usuários.

Este módulo implementa o repositório que realiza operações de banco de dados
relacionadas a usuários, implementando a interface IUserRepository.
"""

from typing import Optional, List, Dict, Any, Union
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fastapi.encoders import jsonable_encoder

from app.adapters.outbound.persistence.repositories.base_repository import CRUDBase
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


class UserCRUD(CRUDBase[User, UserCreate, UserUpdate], IUserRepository):
    """
    Implementação do repositório CRUD para a entidade User.

    Estende CRUDBase com operações específicas para usuários,
    como busca por email e verificação de credenciais.
    """

    def get_by_email(self, db: Session, email: str) -> Optional[User]:
        """
        Busca um usuário pelo email.

        Args:
            db: Sessão do banco de dados
            email: Email do usuário

        Returns:
            User encontrado ou None se não existir

        Raises:
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        try:
            return db.query(User).filter(User.email == email).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao buscar usuário por email '{email}': {e}")
            raise DatabaseOperationException(
                detail="Erro ao buscar usuário por email",
                original_error=e
            )

    def create_with_password(self, db: Session, *, obj_in: UserCreate) -> User:
        """
        Cria um novo usuário com senha segura.

        Args:
            db: Sessão do banco de dados
            obj_in: Dados do usuário a criar

        Returns:
            Novo User criado

        Raises:
            ResourceAlreadyExistsException: Se o email já estiver em uso
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        # Importa gerenciador de senha aqui para evitar ciclo de importação
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Verificar se o email já existe
            if self.get_by_email(db, email=obj_in.email):
                self.logger.warning(f"Tentativa de criar usuário com email já existente: {obj_in.email}")
                raise ResourceAlreadyExistsException(
                    detail=f"Usuário com email '{obj_in.email}' já existe"
                )

            # Verificar força da senha usando domain service
            from app.domain.services.auth_service import PasswordService
            if not PasswordService.verify_password_strength(obj_in.password):
                raise InvalidCredentialsException(
                    detail="A senha não atende aos requisitos mínimos de segurança."
                )

            # Converter schema para dict e extrair senha
            obj_in_data = jsonable_encoder(obj_in)
            password = obj_in_data.pop("password")

            # Criar instância do modelo e atribuir hash da senha
            db_obj = User(**obj_in_data)
            db_obj.password = UserAuthManager.hash_password(password)

            # Adicionar ao grupo 'user' padrão
            user_group = db.query(AuthGroup).filter_by(name="user").first()
            if user_group:
                db_obj.groups.append(user_group)

            # Persistir no banco
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            self.logger.info(f"Usuário criado com email: {db_obj.email}")
            return db_obj

        except ResourceAlreadyExistsException:
            # Repassa exceção de duplicidade
            db.rollback()
            raise
        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao criar usuário: {e}")
            raise DatabaseOperationException(
                detail="Erro ao criar usuário",
                original_error=e
            )

    def update_with_password(
            self,
            db: Session,
            *,
            db_obj: User,
            obj_in: Union[UserUpdate, Dict[str, Any]]
    ) -> User:
        """
        Atualiza um usuário, incluindo opcionalmente a senha.

        Args:
            db: Sessão do banco de dados
            db_obj: Objeto User a ser atualizado
            obj_in: Dados de atualização

        Returns:
            User atualizado

        Raises:
            ResourceAlreadyExistsException: Se o novo email já estiver em uso
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Converter update data para dict
            update_data = (
                obj_in if isinstance(obj_in, dict) else obj_in.dict(exclude_unset=True)
            )

            # Verificar conflito de email
            if "email" in update_data and update_data["email"] != db_obj.email:
                existing = self.get_by_email(db, email=update_data["email"])
                if existing and existing.id != db_obj.id:
                    raise ResourceAlreadyExistsException(
                        detail=f"Email '{update_data['email']}' já está em uso"
                    )

            # Processar senha
            if "password" in update_data and update_data["password"]:
                # Verificar força da senha usando domain service
                from app.domain.services.auth_service import PasswordService
                if PasswordService.verify_password_strength(update_data["password"]):
                    update_data["password"] = UserAuthManager.hash_password(update_data["password"])
                else:
                    raise InvalidCredentialsException(
                        detail="A senha não atende aos requisitos mínimos de segurança."
                    )
            elif "password" in update_data:
                # Remover senha vazia
                del update_data["password"]

            # Usar método genérico para update
            return super().update(db, db_obj=db_obj, obj_in=update_data)

        except ResourceAlreadyExistsException:
            # Repassar a exceção
            db.rollback()
            raise
        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao atualizar usuário: {e}")
            raise DatabaseOperationException(
                detail="Erro ao atualizar usuário",
                original_error=e
            )

    def authenticate(self, db: Session, *, email: str, password: str) -> Optional[User]:
        """
        Autentica um usuário verificando email e senha.

        Args:
            db: Sessão do banco de dados
            email: Email do usuário
            password: Senha em texto plano

        Returns:
            User autenticado ou None

        Raises:
            InvalidCredentialsException: Se credenciais forem inválidas
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        from app.adapters.outbound.security.auth_user_manager import UserAuthManager

        try:
            # Buscar usuário pelo email
            user = self.get_by_email(db, email=email)
            if not user:
                self.logger.warning(f"Tentativa de login com email inexistente: {email}")
                raise InvalidCredentialsException(detail="Email ou senha incorretos")

            # Verificar se usuário está ativo
            if not user.is_active:
                self.logger.warning(f"Tentativa de login com usuário inativo: {email}")
                raise InvalidCredentialsException(detail="Usuário inativo")

            # Verificar senha
            if not UserAuthManager.verify_password(password, user.password):
                self.logger.warning(f"Tentativa de login com senha incorreta: {email}")
                raise InvalidCredentialsException(detail="Email ou senha incorretos")

            return user

        except InvalidCredentialsException:
            # Repassar a exceção
            raise
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao autenticar usuário: {e}")
            raise DatabaseOperationException(
                detail="Erro ao autenticar usuário",
                original_error=e
            )

    def activate_deactivate(self, db: Session, *, user_id: UUID, is_active: bool) -> User:
        """
        Ativa ou desativa um usuário.

        Args:
            db: Sessão do banco de dados
            user_id: ID do usuário
            is_active: Novo status (True para ativo, False para inativo)

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário não for encontrado
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        try:
            # Buscar usuário
            user = self.get(db, id=user_id)
            if not user:
                raise ResourceNotFoundException(
                    detail=f"Usuário com ID {user_id} não encontrado",
                    resource_id=user_id
                )

            # Atualizar status
            user.is_active = is_active

            # Salvar alterações
            db.add(user)
            db.commit()
            db.refresh(user)

            status_text = "ativado" if is_active else "desativado"
            self.logger.info(f"Usuário {user.id} {status_text}")
            return user

        except ResourceNotFoundException:
            # Repassar a exceção
            db.rollback()
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao alterar status do usuário: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao {'ativar' if is_active else 'desativar'} usuário",
                original_error=e
            )

    def get_users_with_permissions(
            self,
            db: Session,
            *,
            skip: int = 0,
            limit: int = 100,
            include_inactive: bool = False
    ) -> List[User]:
        """
        Lista usuários com seus grupos e permissões carregados.

        Args:
            db: Sessão do banco de dados
            skip: Registros a pular (para paginação)
            limit: Máximo de registros a retornar
            include_inactive: Se deve incluir usuários inativos

        Returns:
            Lista de usuários com grupos e permissões

        Raises:
            DatabaseOperationException: Em caso de erro de banco de dados
        """
        try:
            from sqlalchemy.orm import joinedload
            from app.adapters.outbound.persistence.models.auth_group import AuthGroup

            query = db.query(User)

            # Filtrar usuários ativos/inativos
            if not include_inactive:
                query = query.filter(User.is_active == True)

            # Carregar relacionamentos eager (grupos e permissões)
            query = query.options(
                joinedload(User.groups).joinedload(AuthGroup.permissions),
                joinedload(User.permissions)
            )

            # Aplicar paginação
            query = query.offset(skip).limit(limit)

            return query.all()

        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao listar usuários com permissões: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao listar usuários com permissões",
                original_error=e
            )

    def to_domain(self, db_model: User) -> DomainUser:
        """
        Converte modelo de banco de dados para modelo de domínio.

        Args:
            db_model: Modelo ORM do usuário

        Returns:
            Modelo de domínio do usuário
        """
        from app.domain.models.user_domain_model import Group, Permission

        # Converter grupos
        groups = []
        for group_model in db_model.groups:
            # Converter permissões do grupo
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

        # Converter permissões diretas
        permissions = []
        for perm_model in db_model.permissions:
            permission = Permission(
                id=perm_model.id,
                name=perm_model.name,
                codename=perm_model.codename,
                content_type_id=perm_model.content_type_id
            )
            permissions.append(permission)

        # Criar modelo de domínio
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

    def delete(self, db: Session, *, id: Any) -> None:
        """
        Delete a user by ID.

        Args:
            db: Database session
            id: ID of the user to delete

        Raises:
            ResourceNotFoundException: If the user is not found
        """
        user = self.get(db, id=id)
        if not user:
            raise ResourceNotFoundException(
                detail=f"User with ID {id} not found",
                resource_id=id
            )

        db.delete(user)
        db.commit()
        return user

    def list(self, db: Session, *, skip: int = 0, limit: int = 100, **filters) -> List[User]:
        """
        List users with optional filtering.

        Args:
            db: Database session
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            **filters: Additional filters

        Returns:
            List of User objects
        """
        return self.get_multi(db, skip=skip, limit=limit, **filters)


# instância pública que será usada pelos use cases
user = UserCRUD(User)
