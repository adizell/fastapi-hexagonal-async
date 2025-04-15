# app/adapters/outbound/persistence/seeds/__init__.py

"""
Módulo de seeds para inicialização do banco de dados.

Este módulo contém funções para popular o banco de dados
com dados iniciais necessários para o funcionamento do sistema.
"""

import logging
from sqlalchemy.orm import Session

from app.adapters.outbound.persistence.seeds.permissions import run_permissions_seed

# Configurar logger
logger = logging.getLogger(__name__)


def run_all_seeds(db: Session) -> None:
    """
    Executa todos os scripts de seed em ordem.

    Args:
        db: Sessão do banco de dados
    """
    logger.info("Iniciando execução de todos os seeds")

    # Executar seeds na ordem correta (garantindo dependências)
    run_permissions_seed(db)

    logger.info("Todos os seeds foram executados com sucesso")


if __name__ == "__main__":
    """
    Ponto de entrada para execução direta do módulo.

    Permite executar todos os seeds via linha de comando:
    `python -m app.db.seeds`
    """
    from app.adapters.outbound.persistence.database import Session

    # Criar sessão
    session = Session()

    try:
        # Executar todos os seeds
        run_all_seeds(session)

    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao executar seeds: {str(e)}")
        raise

    finally:
        # Fechar sessão
        session.close()
