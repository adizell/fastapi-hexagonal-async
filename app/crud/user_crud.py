# app/crud/user_crud.py

"""
Repositório CRUD para usuários.

Este módulo implementa operações específicas de banco de dados
para a entidade User, estendendo a funcionalidade básica do CRUDBase.
"""

from typing import Optional, List, Dict, Any, Union
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fastapi.encoders import jsonable_encoder

from app.crud.base import CRUDBase
from app.db.models.user import User
from app.application.dtos.user_schemas import UserCreate, UserUpdate
from app.core.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    DatabaseOperationException,
    InvalidCredentialsException
)
from app.adapters.outbound.security.auth_user_manager import UserAuthManager


class UserCRUD(CRUDBase[User, UserCreate, UserUpdate]):
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
            email: Email do usuário a buscar

        Returns:
            Usuário encontrado ou None se não existir

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            return db.query(User).filter(User.email == email).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao buscar usuário por email '{email}': {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao buscar usuário por email",
                original_error=e
            )

    def create_with_password(self, db: Session, *, obj_in: UserCreate) -> User:
        """
        Cria um novo usuário, fazendo hash da senha.

        Args:
            db: Sessão do banco de dados
            obj_in: Dados do usuário a criar

        Returns:
            Novo usuário criado

        Raises:
            ResourceAlreadyExistsException: Se já existir usuário com o mesmo email
            DatabaseOperationException: Se ocorrer outro erro de banco
        """
        try:
            # Verificar se email já existe
            if self.get_by_email(db, email=obj_in.email):
                self.logger.warning(f"Tentativa de criar usuário com email já existente: {obj_in.email}")
                raise ResourceAlreadyExistsException(
                    detail=f"Usuário com email '{obj_in.email}' já existe"
                )

            # Converter objeto Pydantic para dict
            obj_in_data = jsonable_encoder(obj_in)

            # Remover a senha do dict para não ser inserida em texto plano
            password = obj_in_data.pop("password")

            # Criar objeto do modelo
            db_obj = User(**obj_in_data)

            # Gerar hash da senha e atribuir ao modelo
            db_obj.password = UserAuthManager.hash_password(password)

            # Salvar no banco
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)

            self.logger.info(f"Usuário criado com email: {db_obj.email}")
            return db_obj

        except ResourceAlreadyExistsException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao criar usuário: {str(e)}")
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
        Atualiza um usuário existente, tratando a senha de forma segura.

        Args:
            db: Sessão do banco de dados
            db_obj: Usuário a ser atualizado
            obj_in: Dados de atualização

        Returns:
            Usuário atualizado

        Raises:
            ResourceAlreadyExistsException: Se o novo email já existir
            DatabaseOperationException: Se ocorrer outro erro de banco
        """
        try:
            # Converter para dict se for objeto Pydantic
            update_data = obj_in if isinstance(obj_in, dict) else obj_in.dict(exclude_unset=True)

            # Verificar se há atualização de email e se o novo email já existe
            if "email" in update_data and update_data["email"] != db_obj.email:
                existing_user = self.get_by_email(db, email=update_data["email"])
                if existing_user and existing_user.id != db_obj.id:
                    self.logger.warning(
                        f"Tentativa de atualizar usuário para email já existente: {update_data['email']}")
                    raise ResourceAlreadyExistsException(
                        detail=f"Email '{update_data['email']}' já está em uso"
                    )

            # Tratamento especial para senha
            if "password" in update_data and update_data["password"]:
                hashed_password = UserAuthManager.hash_password(update_data["password"])
                # Substituir senha em texto plano pelo hash
                update_data["password"] = hashed_password
            elif "password" in update_data:
                # Remover senha vazia ou None para não atualizar
                del update_data["password"]

            # Usar método da classe base para a atualização
            return super().update(db, db_obj=db_obj, obj_in=update_data)

        except ResourceAlreadyExistsException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao atualizar usuário: {str(e)}")
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
            Usuário autenticado ou None se as credenciais forem inválidas

        Raises:
            InvalidCredentialsException: Se as credenciais forem inválidas
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            # Buscar usuário por email
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
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao autenticar usuário: {str(e)}")
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
            is_active: Novo status (True=ativo, False=inativo)

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário não existir
            DatabaseOperationException: Se ocorrer erro na atualização
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
            # Repassar a exceção já formatada
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
            include_inactive: Se True, inclui usuários inativos

        Returns:
            Lista de usuários com grupos e permissões

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            query = db.query(User)

            # Filtrar usuários ativos/inativos
            if not include_inactive:
                query = query.filter(User.is_active == True)

            # Carregar relacionamentos eager (grupos e permissões)
            query = query.options(
                orm.joinedload(User.groups).joinedload(AuthGroup.permissions),
                orm.joinedload(User.permissions)
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

    def add_to_group(self, db: Session, *, user_id: UUID, group_id: int) -> User:
        """
        Adiciona um usuário a um grupo de permissões.

        Args:
            db: Sessão do banco de dados
            user_id: ID do usuário
            group_id: ID do grupo

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário ou grupo não existir
            DatabaseOperationException: Se ocorrer erro na atualização
        """
        try:
            # Buscar usuário
            user = self.get(db, id=user_id)
            if not user:
                raise ResourceNotFoundException(
                    detail=f"Usuário com ID {user_id} não encontrado",
                    resource_id=user_id
                )

            # Buscar grupo
            group = db.query(AuthGroup).get(group_id)
            if not group:
                raise ResourceNotFoundException(
                    detail=f"Grupo com ID {group_id} não encontrado",
                    resource_id=group_id
                )

            # Verificar se o usuário já está no grupo
            if group in user.groups:
                self.logger.info(f"Usuário {user.id} já pertence ao grupo {group.name}")
                return user

            # Adicionar usuário ao grupo
            user.groups.append(group)

            # Salvar alterações
            db.add(user)
            db.commit()
            db.refresh(user)

            self.logger.info(f"Usuário {user.id} adicionado ao grupo {group.name}")
            return user

        except ResourceNotFoundException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao adicionar usuário ao grupo: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao adicionar usuário ao grupo",
                original_error=e
            )

    def remove_from_group(self, db: Session, *, user_id: UUID, group_id: int) -> User:
        """
        Remove um usuário de um grupo de permissões.

        Args:
            db: Sessão do banco de dados
            user_id: ID do usuário
            group_id: ID do grupo

        Returns:
            Usuário atualizado

        Raises:
            ResourceNotFoundException: Se o usuário ou grupo não existir
            DatabaseOperationException: Se ocorrer erro na atualização
        """
        try:
            # Buscar usuário
            user = self.get(db, id=user_id)
            if not user:
                raise ResourceNotFoundException(
                    detail=f"Usuário com ID {user_id} não encontrado",
                    resource_id=user_id
                )

            # Buscar grupo
            group = db.query(AuthGroup).get(group_id)
            if not group:
                raise ResourceNotFoundException(
                    detail=f"Grupo com ID {group_id} não encontrado",
                    resource_id=group_id
                )

            # Verificar se o usuário está no grupo
            if group not in user.groups:
                self.logger.info(f"Usuário {user.id} não pertence ao grupo {group.name}")
                return user

            # Remover usuário do grupo
            user.groups.remove(group)

            # Salvar alterações
            db.add(user)
            db.commit()
            db.refresh(user)

            self.logger.info(f"Usuário {user.id} removido do grupo {group.name}")
            return user

        except ResourceNotFoundException:
            # Repassar a exceção já formatada
            raise

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao remover usuário do grupo: {str(e)}")
            raise DatabaseOperationException(
                detail="Erro ao remover usuário do grupo",
                original_error=e
            )


# Instância singleton do CRUD para ser usada pelos serviços
user = UserCRUD(User)
