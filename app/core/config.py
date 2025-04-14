# app/core/config.py

from pydantic import PostgresDsn, field_validator, ConfigDict
from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    # App
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int

    # Ambiente da aplicação
    ENVIRONMENT: str = "development"  # Valores possíveis: "development", "production", "testing"

    # Auth
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_USER_EXPIRE_MINUTOS: int
    ACCESS_TOKEN_CLIENT_EXPIRE_DIAS: int

    # Proteção CSRF
    BASE_URL: str = "http://localhost:8000"  # URL base da aplicação
    ALLOWED_ORIGINS: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]  # Origens permitidas
    CSRF_EXEMPT_ROUTES: List[str] = ["/user/login", "/user/register", "/docs", "/redoc",
                                     "/openapi.json"]  # Rotas isentas

    # Controle de visibilidade das rotas na documentação
    SCHEMA_VISIBILITY: bool = False  # True para mostrar todas as rotas, False para ocultar rotas sensíveis

    # Database
    TEST_MODE: bool = False
    DB_URL: Optional[str] = None
    DB_URL_TEST: Optional[str] = None

    PGADMIN_DEFAULT_EMAIL: Optional[str] = None
    PGADMIN_DEFAULT_PASSWORD: Optional[str] = None

    DATABASE_URL: Optional[PostgresDsn] = None

    @field_validator("DATABASE_URL", mode="before")
    def assemble_db_url(cls, value, info):
        if value:
            return value

        data = info.data

        # Use a URL diretamente se estiver disponível e em modo de teste
        if data.get("TEST_MODE") and data.get("DB_URL_TEST"):
            return data.get("DB_URL_TEST")

        # Use a URL diretamente se disponível
        if data.get("DB_URL"):
            return data.get("DB_URL")

        # Imprimir os valores para debug
        print(f"Construindo URL de conexão com: {data}")

        # Construir a URL sem a barra no caminho
        return PostgresDsn.build(
            scheme="postgresql+psycopg2",
            username=data["POSTGRES_USER"],
            password=data["POSTGRES_PASSWORD"],
            host=data["POSTGRES_HOST"],
            port=data["POSTGRES_PORT"],
            path=data["POSTGRES_DB"],
        )

    model_config = ConfigDict(env_file=".env")


settings = Settings()
