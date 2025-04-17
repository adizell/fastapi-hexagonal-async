# app/application/dtos/user_dto.py

"""
Schemas para dados de usuário.

Este módulo define os dtos Pydantic para validação e serialização
dos dados relacionados a usuários, incluindo registro, login,
manipulação de perfil e autenticação.
"""

from uuid import UUID
from datetime import datetime
from typing import Optional
from app.application.dtos.base_dto import CustomBaseModel
from app.shared.utils.input_validation import InputValidator
from pydantic import (
    field_validator,
    EmailStr,
    constr,
    Field,
)


class UserBase(CustomBaseModel):
    """
    Schema base para dados de usuário.

    Contém os atributos comuns a todos os dtos de usuário.
    """
    email: EmailStr = Field(
        ...,
        description="Email do usuário. Deve ser um email válido e único.",
    )

    @field_validator('email')
    def validate_email_security(cls, v):
        """
        Valida a segurança do email para evitar injeções.

        Args:
            v: Email a ser validado

        Returns:
            Email validado

        Raises:
            ValueError: Se o email for inválido
        """
        is_valid, error_msg = InputValidator.validate_email(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


class UserCreate(UserBase):
    """
    Schema para criação de um novo usuário.

    Estende UserBase e adiciona a senha.
    """
    password: constr(min_length=6) = Field(
        ..., description="Senha do usuário, com no mínimo 6 caracteres."
    )

    @field_validator('password')
    def validate_password_security(cls, v):
        """
        Valida a senha para garantir requisitos mínimos de segurança.

        Args:
            v: Senha a ser validada

        Returns:
            Senha validada

        Raises:
            ValueError: Se a senha não atender aos requisitos
        """
        is_valid, error_msg = InputValidator.validate_password(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


class UserOutput(UserBase):
    """
    Schema para retorno de dados de usuário.

    Utilizado para retornar dados do usuário nas APIs sem expor dados sensíveis.
    """
    id: UUID = Field(..., description="Identificador único do usuário.")
    is_active: bool = Field(..., description="Indica se o usuário está ativo.")
    created_at: datetime = Field(..., description="Data e hora de criação do usuário.")
    is_superuser: bool = Field(..., description="Indica se o usuário é um superusuário.")
    updated_at: Optional[datetime] = Field(None, description="Data e hora da última atualização.")

    class Config:
        from_attributes = True


class UserSelfUpdate(CustomBaseModel):
    """
    Schema para usuários atualizarem seus próprios dados.

    Permite apenas atualização de email e password.
    """
    email: Optional[EmailStr] = Field(
        None,
        description="Email do usuário. Deve ser um email válido e único.",
    )
    password: Optional[constr(min_length=6)] = Field(
        None, description="Nova senha do usuário, com no mínimo 6 caracteres."
    )
    current_password: Optional[str] = Field(
        None, description="Senha atual (necessária para confirmar alterações)."
    )


class UserUpdate(CustomBaseModel):
    """
    Schema para administradores atualizarem qualquer usuário.

    Permite atualização de email, password, status ativo e status de superusuário.
    """
    email: Optional[EmailStr] = Field(
        None,
        description="Email do usuário. Deve ser um email válido e único.",
    )
    password: Optional[constr(min_length=6)] = Field(
        None, description="Nova senha do usuário, com no mínimo 6 caracteres."
    )
    is_active: Optional[bool] = Field(
        None, description="Define se o usuário está ativo ou inativo."
    )
    is_superuser: Optional[bool] = Field(
        None, description="Define se o usuário é um superusuário."
    )


class UserListOutput(CustomBaseModel):
    """
    Schema para listar usuários.

    Utilizado nas APIs de listagem de usuários.
    """
    id: UUID
    email: str
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


########################################################################
# Para manter compatibilidade com código que usava `User`
# você pode fazer isso no final do arquivo:
########################################################################
User = UserCreate


########################################################################
# Classe para Token de autenticação
########################################################################
class TokenData(CustomBaseModel):
    """
    Schema para dados de token de autenticação.

    Utilizado para retornar o token JWT e informações de expiração.
    """
    access_token: str = Field(..., description="Token JWT de acesso.")
    refresh_token: str = Field(..., description="Token de atualização para obter novos tokens de acesso.")
    expires_at: datetime = Field(..., description="Data e hora de expiração do token.")

    class Config:
        from_attributes = True


class RefreshTokenRequest(CustomBaseModel):
    """
    Schema para solicitação de refresh token.
    """
    refresh_token: str = Field(..., description="Token de atualização para obter um novo token de acesso.")
