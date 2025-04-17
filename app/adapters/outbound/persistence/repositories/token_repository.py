# app/adapters/outbound/persistence/repositories/token_repository.py

from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.adapters.outbound.persistence.models.token_blacklist import TokenBlacklist
from app.domain.exceptions import DatabaseOperationException


class TokenRepository:
    """Repository for managing token blacklist."""

    @staticmethod
    def add_to_blacklist(db: Session, jti: str, expires_at: datetime) -> TokenBlacklist:
        """
        Add a token to the blacklist.

        Args:
            db: Database session
            jti: JWT ID to blacklist
            expires_at: When the token naturally expires

        Returns:
            The created TokenBlacklist record
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
                detail="Error adding token to blacklist",
                original_error=e
            )

    @staticmethod
    def is_blacklisted(db: Session, jti: str) -> bool:
        """
        Check if a token is in the blacklist.

        Args:
            db: Database session
            jti: JWT ID to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        try:
            token = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
            return token is not None
        except SQLAlchemyError as e:
            raise DatabaseOperationException(
                detail="Error checking token blacklist",
                original_error=e
            )

    @staticmethod
    def cleanup_expired(db: Session) -> int:
        """
        Remove expired tokens from blacklist to keep the table size manageable.

        Args:
            db: Database session

        Returns:
            Number of records deleted
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
                detail="Error cleaning up expired blacklisted tokens",
                original_error=e
            )


# Create instance
token_repository = TokenRepository()
