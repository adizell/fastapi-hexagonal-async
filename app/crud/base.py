# app/crud/base.py

"""
Módulo base para todos os repositórios CRUD.

Este módulo define a classe CRUDBase que implementa operações padrão
de Create, Read, Update e Delete para entidades do sistema.
"""

from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging

from app.db.base import Base
from app.core.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    DatabaseOperationException
)

# Define tipo genérico para modelos SQLAlchemy
ModelType = TypeVar("ModelType", bound=Base)
# Define tipos genéricos para dtos Pydantic
CreateSchemaType = TypeVar("CreateSchemaType")
UpdateSchemaType = TypeVar("UpdateSchemaType")

# Configurar logger
logger = logging.getLogger(__name__)


class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """
    Classe base para implementação do padrão Repository.

    Fornece operações CRUD genéricas que podem ser usadas por qualquer entidade.
    Inclui tratamento de erros e logging consistentes.

    Attributes:
        model: Classe do modelo SQLAlchemy
        logger: Logger configurado para a classe
    """

    def __init__(self, model: Type[ModelType]):
        """
        Inicializa o repositório com o modelo SQLAlchemy.

        Args:
            model: Classe do modelo SQLAlchemy associado a este repositório
        """
        self.model = model
        self.logger = logging.getLogger(f"{__name__}.{model.__name__}")

    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        """
        Obtém uma entidade pelo ID.

        Args:
            db: Sessão do banco de dados
            id: ID da entidade

        Returns:
            Entidade encontrada ou None se não existir
        """
        try:
            return db.query(self.model).filter(self.model.id == id).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao buscar {self.model.__name__} com ID {id}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao buscar {self.model.__name__}",
                original_error=e
            )

    def get_by_field(self, db: Session, field_name: str, value: Any) -> Optional[ModelType]:
        """
        Obtém uma entidade pelo valor de um campo específico.

        Args:
            db: Sessão do banco de dados
            field_name: Nome do campo/coluna a filtrar
            value: Valor a ser filtrado

        Returns:
            Entidade encontrada ou None se não existir

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            return db.query(self.model).filter(getattr(self.model, field_name) == value).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao buscar {self.model.__name__} com {field_name}={value}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao buscar {self.model.__name__} por {field_name}",
                original_error=e
            )

    def exists(self, db: Session, **filters) -> bool:
        """
        Verifica se existe uma entidade com os filtros especificados.

        Args:
            db: Sessão do banco de dados
            **filters: Filtros no formato campo=valor

        Returns:
            True se existir, False caso contrário

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            query = db.query(self.model)
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)

            return db.query(query.exists()).scalar()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao verificar existência de {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao verificar existência de {self.model.__name__}",
                original_error=e
            )

    def get_multi(
            self, db: Session, *, skip: int = 0, limit: int = 100, **filters
    ) -> List[ModelType]:
        """
        Obtém múltiplas entidades com paginação e filtros opcionais.

        Args:
            db: Sessão do banco de dados
            skip: Número de registros a pular (para paginação)
            limit: Número máximo de registros a retornar
            **filters: Filtros adicionais no formato campo=valor

        Returns:
            Lista de entidades encontradas

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            query = db.query(self.model)

            # Aplicar filtros dinâmicos
            for field, value in filters.items():
                if hasattr(self.model, field) and value is not None:
                    if isinstance(value, str) and value.startswith("%") and value.endswith("%"):
                        # Filtro LIKE para strings com wildcards
                        query = query.filter(getattr(self.model, field).ilike(value))
                    else:
                        # Filtro de igualdade padrão
                        query = query.filter(getattr(self.model, field) == value)

            return query.offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao listar {self.model.__name__}s: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao listar {self.model.__name__}s",
                original_error=e
            )

    def create(self, db: Session, *, obj_in: CreateSchemaType) -> ModelType:
        """
        Cria uma nova entidade.

        Args:
            db: Sessão do banco de dados
            obj_in: Schema de criação com os dados da entidade

        Returns:
            Nova entidade criada

        Raises:
            ResourceAlreadyExistsException: Se a entidade já existir
            DatabaseOperationException: Se ocorrer outro erro de banco
        """
        try:
            # Converter schema Pydantic para dicionário
            obj_in_data = jsonable_encoder(obj_in)

            # Criar instância do modelo com os dados
            db_obj = self.model(**obj_in_data)

            # Adicionar e persistir no banco
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)

            self.logger.info(f"{self.model.__name__} criado com ID: {db_obj.id}")
            return db_obj

        except IntegrityError as e:
            db.rollback()
            error_msg = str(e).lower()
            if 'unique' in error_msg or 'duplicate' in error_msg:
                self.logger.warning(f"Tentativa de criar {self.model.__name__} duplicado: {str(e)}")
                raise ResourceAlreadyExistsException(
                    detail=f"{self.model.__name__} com esses dados já existe"
                )
            else:
                self.logger.error(f"Erro de integridade ao criar {self.model.__name__}: {str(e)}")
                raise DatabaseOperationException(original_error=e)

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao criar {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao criar {self.model.__name__}",
                original_error=e
            )

    def update(
            self, db: Session, *, db_obj: ModelType, obj_in: Union[UpdateSchemaType, Dict[str, Any]]
    ) -> ModelType:
        """
        Atualiza uma entidade existente.

        Args:
            db: Sessão do banco de dados
            db_obj: Instância do modelo a ser atualizada
            obj_in: Schema de atualização ou dicionário com os dados a atualizar

        Returns:
            Entidade atualizada

        Raises:
            ResourceAlreadyExistsException: Se a atualização violar restrição de unicidade
            DatabaseOperationException: Se ocorrer outro erro de banco
        """
        try:
            # Obter os dados atuais da entidade
            obj_data = jsonable_encoder(db_obj)

            # Preparar os dados de atualização
            if isinstance(obj_in, dict):
                update_data = obj_in
            else:
                update_data = obj_in.dict(exclude_unset=True)

            # Atualizar cada campo conforme os novos valores
            for field in obj_data:
                if field in update_data:
                    setattr(db_obj, field, update_data[field])

            # Salvar as alterações
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)

            self.logger.info(f"{self.model.__name__} com ID {db_obj.id} atualizado")
            return db_obj

        except IntegrityError as e:
            db.rollback()
            error_msg = str(e).lower()
            if 'unique' in error_msg or 'duplicate' in error_msg:
                self.logger.warning(f"Violação de unicidade ao atualizar {self.model.__name__}: {str(e)}")
                raise ResourceAlreadyExistsException(
                    detail=f"Não foi possível atualizar {self.model.__name__}: valor já existe"
                )
            else:
                self.logger.error(f"Erro de integridade ao atualizar {self.model.__name__}: {str(e)}")
                raise DatabaseOperationException(original_error=e)

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao atualizar {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao atualizar {self.model.__name__}",
                original_error=e
            )

    def remove(self, db: Session, *, id: Any) -> ModelType:
        """
        Remove uma entidade pelo ID.

        Args:
            db: Sessão do banco de dados
            id: ID da entidade a remover

        Returns:
            Entidade removida

        Raises:
            ResourceNotFoundException: Se a entidade não existir
            DatabaseOperationException: Se ocorrer erro na remoção
        """
        try:
            # Buscar a entidade
            obj = db.query(self.model).get(id)
            if not obj:
                raise ResourceNotFoundException(
                    detail=f"{self.model.__name__} com ID {id} não encontrado",
                    resource_id=id
                )

            # Remover a entidade
            db.delete(obj)
            db.commit()

            self.logger.info(f"{self.model.__name__} com ID {id} removido")
            return obj

        except IntegrityError as e:
            db.rollback()
            self.logger.error(f"Erro de integridade ao remover {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Não é possível remover {self.model.__name__} pois está sendo usado por outras entidades",
                original_error=e
            )

        except SQLAlchemyError as e:
            db.rollback()
            self.logger.error(f"Erro ao remover {self.model.__name__}: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao remover {self.model.__name__}",
                original_error=e
            )

    def count(self, db: Session, **filters) -> int:
        """
        Conta o número de entidades que correspondem aos filtros.

        Args:
            db: Sessão do banco de dados
            **filters: Filtros no formato campo=valor

        Returns:
            Número de entidades correspondentes aos filtros

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            query = db.query(self.model)

            # Aplicar filtros
            for field, value in filters.items():
                if hasattr(self.model, field) and value is not None:
                    query = query.filter(getattr(self.model, field) == value)

            return query.count()

        except SQLAlchemyError as e:
            self.logger.error(f"Erro ao contar {self.model.__name__}s: {str(e)}")
            raise DatabaseOperationException(
                detail=f"Erro ao contar {self.model.__name__}s",
                original_error=e
            )
