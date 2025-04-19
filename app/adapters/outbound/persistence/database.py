# app/adapters/outbound/persistence/database.py (async version)

import time
import logging
from typing import AsyncGenerator
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base

from app.adapters.configuration.config import settings

# Configure logger
logger = logging.getLogger(__name__)

# ─── Definição do Base ─────────────────────────────────────────────────────────
# Cria a classe pai de todos os modelos ORM para controle de metadados
Base = declarative_base()
# ────────────────────────────────────────────────────────────────────────────────

# Build async database URL trocando psycopg2 por asyncpg
database_url = str(settings.DATABASE_URL).replace('postgresql+psycopg2', 'postgresql+asyncpg')
logger.info(f"Connecting to database: {database_url.split('@')[-1]}")

try:
    # Create async engine
    engine = create_async_engine(
        database_url,
        echo=False,
        future=True,
        pool_size=20,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=True
    )

    # Create async session factory
    AsyncSessionLocal = async_sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False,
    )

    logger.info("Async database connection configured successfully")

except SQLAlchemyError as e:
    logger.error(f"Error connecting to database: {str(e)}")
    raise


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Provides an async context for database operations,
    ensuring the session is closed at the end.

    Yields:
        AsyncSession: SQLAlchemy async session

    Example:
        ```python
        async with get_db_context() as db:
            users = await db.execute(select(User))
            result = users.scalars().all()
        ```
    """
    session = AsyncSessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection for use with FastAPI.

    Yields:
        AsyncSession: SQLAlchemy async session

    Example:
        ```python
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            query = select(User)
            result = await db.execute(query)
            return result.scalars().all()
        ```
    """
    async with get_db_context() as session:
        yield session


# For compatibility with existing code
AsyncSession = AsyncSession
