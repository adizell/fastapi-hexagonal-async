# app/adapters/outbound/persistence/repositories/token_repository.py

"""
Repositório para gerenciamento de tokens.

Este módulo implementa operações de banco de dados
para tokens revogados ou expirados.
"""

from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.adapters.outbound.persistence.repositories.base_repository import CRUDBase
from app.adapters.outbound.persistence.models.token_blacklist import TokenBlacklist
from app.domain.exceptions import DatabaseOperationException


class TokenCRUD(CRUDBase[TokenBlacklist, dict, dict]):
    """
    Implementação do repositório CRUD para a entidade TokenBlacklist.

    Estende CRUDBase com operações específicas para tokens.
    """

    def add_to_blacklist(self, db: Session, jti: str, expires_at: datetime) -> TokenBlacklist:
        """
        Adiciona um token à blacklist.

        Args:
            db: Sessão do banco de dados
            jti: Identificador único do token (JWT ID)
            expires_at: Data e hora de expiração do token

        Returns:
            Token adicionado à blacklist

        Raises:
            DatabaseOperationException: Se ocorrer erro ao adicionar à blacklist
        """
        try:
            token = TokenBlacklist(
                jti=jti,
                expires_at=expires_at,
                revoked_at=datetime.utcnow()
            )
            db.add(token)
            db.commit()
            db.refresh(token)
            return token
        except SQLAlchemyError as e:
            db.rollback()
            raise DatabaseOperationException(
                detail="Erro ao adicionar token à blacklist",
                original_error=e
            )

    def is_blacklisted(self, db: Session, jti: str) -> bool:
        """
        Verifica se um token está na blacklist.

        Args:
            db: Sessão do banco de dados
            jti: Identificador único do token (JWT ID)

        Returns:
            True se o token estiver na blacklist, False caso contrário

        Raises:
            DatabaseOperationException: Se ocorrer erro na consulta
        """
        try:
            token = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
            return token is not None
        except SQLAlchemyError as e:
            raise DatabaseOperationException(
                detail="Erro ao verificar token na blacklist",
                original_error=e
            )

    def cleanup_expired(self, db: Session) -> int:
        """
        Remove tokens expirados da blacklist.

        Args:
            db: Sessão do banco de dados

        Returns:
            Número de tokens removidos

        Raises:
            DatabaseOperationException: Se ocorrer erro na remoção
        """
        try:
            now = datetime.utcnow()
            result = db.query(TokenBlacklist).filter(
                TokenBlacklist.expires_at < now
            ).delete()
            db.commit()
            return result
        except SQLAlchemyError as e:
            db.rollback()
            raise DatabaseOperationException(
                detail="Erro ao limpar tokens expirados",
                original_error=e
            )


# Instância singleton do CRUD para ser usada pelos serviços
token = TokenCRUD(TokenBlacklist)
