# app/application/dtos/client_dto.py

"""
Schemas para dados de client (aplicações/parceiros).

Este módulo define os dtos Pydantic para validação e serialização
dos dados relacionados a clients que acessam a API.
"""

from pydantic import BaseModel, Field


class ClientBase(BaseModel):
    """
    Schema base para dados de client.

    Contém os atributos comuns a todos os dtos de client.
    """
    client_id: str = Field(..., description="Identificador único do client")


class Client(ClientBase):
    """
    Schema completo para client.

    Estende ClientBase e adiciona client_secret e status ativo.
    """
    client_secret: str = Field(..., description="Chave secreta (senha) do client")
    is_active: bool = Field(True, description="Indica se o client está ativo")


class ClientOutput(ClientBase):
    """
    Schema para retorno de dados de client.

    Utilizado para retornar dados do client nas APIs sem expor dados sensíveis.
    """
    is_active: bool = Field(..., description="Indica se o client está ativo")

    class Config:
        from_attributes = True
