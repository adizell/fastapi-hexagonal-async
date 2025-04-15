# migrations/env.py

import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy.pool import QueuePool
from alembic import context

# Ajusta path para poder importar a aplicação
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.config import settings  # <- usa o config.py
from app.adapters.outbound.persistence.models import Base

# Export da URL do banco para uso em outros módulos
DB_URL = str(settings.DATABASE_URL)

# Config Alembic
alembic_config = context.config

# Logging padrão do Alembic
if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

# Seta a URL do banco no alembic.ini dinamicamente
alembic_config.set_main_option("sqlalchemy.url", DB_URL)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Migrations offline"""
    url = alembic_config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Migrations online"""
    connectable = engine_from_config(
        alembic_config.get_section(alembic_config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=QueuePool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
