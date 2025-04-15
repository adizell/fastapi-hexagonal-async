# app/application/dtos/base_dto.py

"""
Classe base para dtos personalizados.

Este módulo define a classe base CustomBaseModel que estende
o BaseModel do Pydantic com funcionalidades adicionais comuns
a todos os dtos da aplicação.
"""

from pydantic import BaseModel
from typing import Any, Dict


class CustomBaseModel(BaseModel):
    """
    Modelo base personalizado para todos os dtos da aplicação.

    Estende o BaseModel do Pydantic adicionando comportamentos personalizados,
    como a exclusão automática de valores None no método dict().
    """

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Sobrescreve o método dict do Pydantic para filtrar campos com valor None.

        Esta função melhora a serialização dos modelos ao omitir campos
        que não possuem valor definido.

        Args:
            *args: Argumentos posicionais passados para o método original
            **kwargs: Argumentos nomeados passados para o método original

        Returns:
            Dict[str, Any]: Dicionário com os atributos do modelo, excluindo valores None
        """
        # Chama a função 'dict' da classe pai (BaseModel) para obter o dicionário padrão dos atributos
        d = super().dict(*args, **kwargs)

        # Filtra o dicionário para remover itens onde o valor é None
        d = {k: v for k, v in d.items() if v is not None}

        # Retorna o dicionário filtrado
        return d
