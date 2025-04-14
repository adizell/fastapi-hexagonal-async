# app/core/database.py

"""
Configuração de conexão com banco de dados.

Este módulo gerencia a conexão com o banco de dados PostgreSQL,
configurando o pool de conexões e fornecendo funções para obter sessões.
"""

import time
import logging
from typing import Generator
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import QueuePool

from app.core.config import settings

# Configurar logger
logger = logging.getLogger(__name__)


def handle_disconnect(dbapi_connection, connection_record, connection_proxy):
    """
    Callback para tratar desconexões de banco de dados.
    Executado sempre que uma conexão é retirada do pool.
    """
    connection_record.info.pop("query_start_time", None)
    connection_record.info.pop("connection_start_time", None)
    try:
        if dbapi_connection is not None and hasattr(dbapi_connection, "ping"):
            dbapi_connection.ping(reconnect=True, attempts=3, delay=5)
    except Exception as e:
        connection_record.invalidate(e)
        logger.warning(f"Conexão com o banco de dados foi invalidada: {str(e)}")


def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """
    Evento executado antes de qualquer query.
    Usado para medição de performance e logging.
    """
    conn.info.setdefault("query_start_time", time.time())
    if settings.ENVIRONMENT == "development":
        logger.debug(f"Executando SQL: {statement}")


def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """
    Evento executado depois de qualquer query.
    Usado para medição de performance e logging.
    """
    total = time.time() - conn.info.pop("query_start_time", time.time())

    # Log de queries lentas
    if total > 0.5:  # queries mais lentas que 500ms
        logger.warning(f"Query lenta ({total:.2f}s): {statement}")
    elif settings.ENVIRONMENT == "development":
        logger.debug(f"Query executada em {total:.2f}s")


# Construir URL da conexão
database_url = str(settings.DATABASE_URL)
logger.info(f"Conectando ao banco de dados: {database_url.split('@')[-1]}")

try:
    # Criar engine com configurações avançadas do pool
    engine = create_engine(
        database_url,
        # Configurações básicas
        echo=False,  # Não logar queries automaticamente (usamos eventos para isso)
        future=True,  # Usar recursos mais recentes do SQLAlchemy
        # Configurações do pool
        poolclass=QueuePool,  # Usar QueuePool (gerenciamento mais sofisticado de conexões)
        pool_pre_ping=True,  # Verificar conexões quebradas antes de usar
        pool_size=20,  # Número de conexões no pool
        max_overflow=10,  # Número extra de conexões além do pool
        pool_timeout=30,  # Tempo máximo para esperar por uma conexão disponível
        pool_recycle=1800,  # Reciclar conexões após 30 minutos (previne conexões zumbis)
    )

    # Registrar eventos para monitorar queries e conexões
    event.listen(engine, "checkout", handle_disconnect)
    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    event.listen(engine, "after_cursor_execute", after_cursor_execute)

    # Session configurada com scoped_session para thread safety
    SessionFactory = sessionmaker(
        autocommit=False,  # Não confirma automaticamente as transações
        autoflush=False,  # Não realiza flush automaticamente em cada query
        bind=engine,  # Define a conexão (engine) utilizada nas sessões
    )

    # Criar scoped session - garante thread safety
    SessionLocal = scoped_session(SessionFactory)

    logger.info("Conexão com o banco de dados configurada com sucesso")

except SQLAlchemyError as e:
    logger.error(f"Erro ao conectar ao banco de dados: {str(e)}")
    raise


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Fornece um contexto para operações de banco de dados,
    garantindo o fechamento da sessão ao final.

    Yields:
        Sessão do SQLAlchemy

    Example:
        ```python
        with get_db_context() as db:
            users = db.query(User).all()
        ```
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency injection para uso com FastAPI.

    Yields:
        Sessão do SQLAlchemy

    Example:
        ```python
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
        ```
    """
    with get_db_context() as session:
        yield session


# Para compatibilidade com código existente
Session = SessionLocal
