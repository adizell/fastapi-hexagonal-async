# app/application/use_cases/base_use_cases.py

"""
Classe base para todos os serviços da aplicação.

Este módulo define a estrutura básica que todos os serviços devem seguir,
promovendo consistência e reutilização de código.
"""

from typing import Generic, TypeVar, Type, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging

from app.adapters.outbound.persistence.models.base_model import Base
from app.domain.exceptions import (
    ResourceNotFoundException,
    ResourceAlreadyExistsException,
    DatabaseOperationException,
    InvalidInputException
)

# Configurar logger
logger = logging.getLogger(__name__)

# Define tipos genéricos para uso nas classes derivadas
ModelType = TypeVar("ModelType", bound=Base)


class BaseService(Generic[ModelType]):
    """
    Classe base para serviços, fornecendo operações CRUD comuns.

    Esta classe implementa funcionalidades compartilhadas por todos os serviços,
    como gestão de sessão, tratamento de exceções e operações básicas no banco de dados.
    """

    def __init__(self, db_session: Session, model_class: Type[ModelType]):
        """
        Inicializa o serviço com uma sessão de banco de dados e a classe do modelo.

        Args:
            db_session: Sessão SQLAlchemy ativa
            model_class: Classe do modelo SQLAlchemy
        """
        self.db_session = db_session
        self.model_class = model_class
        self.model_name = model_class.__name__

    def _get_by_id(self, entity_id: Any) -> ModelType:
        """
        Busca uma entidade pelo ID.

        Args:
            entity_id: Identificador da entidade

        Returns:
            Objeto do modelo encontrado

        Raises:
            ResourceNotFoundException: Se a entidade não for encontrada
        """
        entity = self.db_session.query(self.model_class).filter(
            self.model_class.id == entity_id
        ).first()

        if not entity:
            error_msg = f"{self.model_name} com ID {entity_id} não encontrado"
            logger.warning(error_msg)
            raise ResourceNotFoundException(detail=error_msg, resource_id=entity_id)

        return entity

    def list_all(self, filters: Dict[str, Any] = None, skip: int = 0, limit: int = 100) -> List[ModelType]:
        """
        Lista entidades com filtros opcionais.

        Args:
            filters: Dicionário de filtros a serem aplicados
            skip: Número de registros a pular
            limit: Número máximo de registros a retornar

        Returns:
            Lista de entidades que correspondem aos filtros

        Raises:
            DatabaseOperationException: Em caso de erro no banco de dados
        """
        try:
            query = self.db_session.query(self.model_class)

            # Aplica filtros dinâmicos se fornecidos
            if filters:
                for key, value in filters.items():
                    if value is not None:
                        # Valida se o atributo existe no modelo
                        if hasattr(self.model_class, key):
                            # Se for uma string e tiver o caractere %, aplica LIKE
                            if isinstance(value, str) and "%" in value:
                                query = query.filter(getattr(self.model_class, key).ilike(value))
                            else:
                                query = query.filter(getattr(self.model_class, key) == value)

            return query.offset(skip).limit(limit).all()

        except SQLAlchemyError as e:
            logger.error(f"Erro ao listar {self.model_name}s: {str(e)}")
            raise DatabaseOperationException(original_error=e)

    def create(self, data: Dict[str, Any]) -> ModelType:
        """
        Cria uma nova entidade.

        Args:
            data: Dicionário com os dados da entidade

        Returns:
            Nova entidade criada

        Raises:
            InvalidInputException: Se os dados de entrada forem inválidos
            ResourceAlreadyExistsException: Se uma entidade com atributos únicos já existir
            DatabaseOperationException: Em caso de erro no banco de dados
        """
        try:
            # Cria uma nova instância do modelo
            entity = self.model_class(**data)

            # Adiciona e salva no banco
            self.db_session.add(entity)
            self.db_session.commit()
            self.db_session.refresh(entity)

            logger.info(f"{self.model_name} criado com sucesso: ID {entity.id}")
            return entity

        except IntegrityError as e:
            self.db_session.rollback()
            error_msg = f"Erro de integridade ao criar {self.model_name}: {str(e)}"
            logger.error(error_msg)

            # Verifica se é violação de unicidade
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ResourceAlreadyExistsException(
                    detail=f"{self.model_name} com essas características já existe"
                )

            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except SQLAlchemyError as e:
            self.db_session.rollback()
            error_msg = f"Erro de banco de dados ao criar {self.model_name}: {str(e)}"
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except Exception as e:
            self.db_session.rollback()
            error_msg = f"Erro inesperado ao criar {self.model_name}: {str(e)}"
            logger.exception(error_msg)
            raise

    def update(self, entity_id: Any, data: Dict[str, Any]) -> ModelType:
        """
        Atualiza uma entidade existente.

        Args:
            entity_id: Identificador da entidade
            data: Dicionário com os dados a serem atualizados

        Returns:
            Entidade atualizada

        Raises:
            ResourceNotFoundException: Se a entidade não for encontrada
            InvalidInputException: Se os dados de entrada forem inválidos
            ResourceAlreadyExistsException: Se a atualização violar restrições de unicidade
            DatabaseOperationException: Em caso de erro no banco de dados
        """
        try:
            # Busca a entidade
            entity = self._get_by_id(entity_id)

            # Atualiza os atributos
            for key, value in data.items():
                if hasattr(entity, key) and value is not None:
                    setattr(entity, key, value)

            # Salva as alterações
            self.db_session.commit()
            self.db_session.refresh(entity)

            logger.info(f"{self.model_name} atualizado com sucesso: ID {entity.id}")
            return entity

        except IntegrityError as e:
            self.db_session.rollback()
            error_msg = f"Erro de integridade ao atualizar {self.model_name}: {str(e)}"
            logger.error(error_msg)

            # Verifica se é violação de unicidade
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ResourceAlreadyExistsException(
                    detail=f"As alterações causariam conflito com {self.model_name} existente"
                )

            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except ResourceNotFoundException:
            # Repassa exceção de recurso não encontrado
            self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            self.db_session.rollback()
            error_msg = f"Erro de banco de dados ao atualizar {self.model_name}: {str(e)}"
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except Exception as e:
            self.db_session.rollback()
            error_msg = f"Erro inesperado ao atualizar {self.model_name}: {str(e)}"
            logger.exception(error_msg)
            raise

    def delete(self, entity_id: Any) -> Dict[str, str]:
        """
        Remove uma entidade do banco de dados.

        Args:
            entity_id: Identificador da entidade

        Returns:
            Mensagem de sucesso

        Raises:
            ResourceNotFoundException: Se a entidade não for encontrada
            DatabaseOperationException: Em caso de erro no banco de dados
        """
        try:
            # Busca a entidade
            entity = self._get_by_id(entity_id)

            # Remove do banco
            self.db_session.delete(entity)
            self.db_session.commit()

            logger.info(f"{self.model_name} excluído com sucesso: ID {entity_id}")
            return {"message": f"{self.model_name} excluído com sucesso"}

        except IntegrityError as e:
            self.db_session.rollback()
            error_msg = f"Não é possível excluir {self.model_name} pois está sendo referenciado por outras entidades"
            logger.error(f"{error_msg}: {str(e)}")
            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except ResourceNotFoundException:
            # Repassa exceção de recurso não encontrado
            self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            self.db_session.rollback()
            error_msg = f"Erro de banco de dados ao excluir {self.model_name}: {str(e)}"
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except Exception as e:
            self.db_session.rollback()
            error_msg = f"Erro inesperado ao excluir {self.model_name}: {str(e)}"
            logger.exception(error_msg)
            raise

    def toggle_status(self, entity_id: Any, active: bool) -> ModelType:
        """
        Ativa ou desativa uma entidade.

        Args:
            entity_id: Identificador da entidade
            active: Novo status (True para ativo, False para inativo)

        Returns:
            Entidade atualizada

        Raises:
            ResourceNotFoundException: Se a entidade não for encontrada
            DatabaseOperationException: Em caso de erro no banco de dados
        """
        try:
            # Verifica se a entidade possui o atributo is_active
            if not hasattr(self.model_class, "is_active"):
                raise InvalidInputException(
                    detail=f"O modelo {self.model_name} não suporta a operação de ativar/desativar"
                )

            # Busca a entidade
            entity = self._get_by_id(entity_id)

            # Atualiza o status
            entity.is_active = active
            self.db_session.commit()
            self.db_session.refresh(entity)

            status_text = "ativado" if active else "desativado"
            logger.info(f"{self.model_name} {entity_id} {status_text} com sucesso")
            return entity

        except ResourceNotFoundException:
            # Repassa exceção de recurso não encontrado
            self.db_session.rollback()
            raise

        except SQLAlchemyError as e:
            self.db_session.rollback()
            error_msg = f"Erro de banco de dados ao alterar status de {self.model_name}: {str(e)}"
            logger.error(error_msg)
            raise DatabaseOperationException(detail=error_msg, original_error=e)

        except Exception as e:
            self.db_session.rollback()
            error_msg = f"Erro inesperado ao alterar status de {self.model_name}: {str(e)}"
            logger.exception(error_msg)
            raise
