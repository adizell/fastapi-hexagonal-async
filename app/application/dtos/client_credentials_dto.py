# app/application/dtos/client_credentials_dto.py

"""
Schemas para gerenciamento de clients.

Este módulo define os dtos Pydantic para operações específicas
de gerenciamento de clients, como criação e atualização de credenciais.
"""

from pydantic import BaseModel, Field


class ClientCreateResponse(BaseModel):
    """
    Schema para resposta de criação de client.

    Utilizado para retornar as credenciais geradas para um novo client.
    """
    client_id: str = Field(..., description="Identificador único do client gerado pelo sistema")
    client_secret: str = Field(..., description="Chave secreta (senha) gerada para o client")


class ClientSecretUpdateResponse(BaseModel):
    """
    Schema para resposta de atualização de chave secreta.

    Utilizado para retornar a nova chave secreta gerada durante uma atualização.
    """
    client_id: str = Field(..., description="Identificador do client")
    new_client_secret: str = Field(..., description="Nova chave secreta gerada para o client")


class ClientTokenResponse(BaseModel):
    """
    Schema para resposta de geração de token.

    Utilizado para retornar o token JWT gerado para um client.
    """
    access_token: str = Field(..., description="Token JWT de acesso")
    token_type: str = Field("bearer", description="Tipo do token")
    expires_in: int = Field(..., description="Tempo de expiração em segundos")
