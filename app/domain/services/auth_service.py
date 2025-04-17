# app/domain/services/auth_service.py

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import uuid

from app.domain.models.user_domain_model import User
from app.domain.models.client_domain_model import Client


class AuthService:
    """
    Domain service for authentication-related business logic.
    """

    @staticmethod
    def create_token_payload(
            subject: str,
            expires_delta: timedelta,
            token_type: str,
            additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a token payload with standard claims.

        Args:
            subject: The subject of the token (user ID or client ID)
            expires_delta: Token expiration time delta
            token_type: Type of token (e.g., "user", "client", "refresh")
            additional_claims: Additional claims to include in token

        Returns:
            Dict with all token claims
        """
        expire = datetime.utcnow() + expires_delta
        token_id = str(uuid.uuid4())

        # Create base payload
        payload = {
            "sub": str(subject),
            "exp": int(expire.timestamp()),
            "type": token_type,
            "jti": token_id,
        }

        # Add any additional claims
        if additional_claims:
            payload.update(additional_claims)

        return payload

    @staticmethod
    def is_token_valid(token_payload: Dict[str, Any], expected_type: str) -> bool:
        """
        Validate a token's basic properties.

        Args:
            token_payload: The decoded token payload
            expected_type: Expected token type

        Returns:
            True if token is valid, False otherwise
        """
        # Check if required fields exist
        if not all(k in token_payload for k in ["sub", "exp", "type", "jti"]):
            return False

        # Check token type
        if token_payload.get("type") != expected_type:
            return False

        # Check expiration
        if datetime.fromtimestamp(token_payload["exp"]) < datetime.utcnow():
            return False

        return True


class PasswordService:
    """
    Domain service for password-related operations.

    This service defines the interface for password operations,
    actual implementation will be in the adapters layer.
    """

    @staticmethod
    def verify_password_strength(password: str) -> bool:
        """
        Verify the strength of a password.

        Args:
            password: The password to verify

        Returns:
            True if password meets strength requirements
        """
        # Basic validation - implementation might be more complex
        return (
                len(password) >= 8
                and any(c.isupper() for c in password)
                and any(c.islower() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)
        )
