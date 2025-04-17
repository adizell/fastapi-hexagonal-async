# app/adapters/configuration/config.py

from typing import Optional, List, Union
from logging import getLevelName
from pydantic import PostgresDsn, field_validator, ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Logging
    LOG_LEVEL: str = "INFO"

    # Environment
    ENVIRONMENT: str = "development"  # "development", "production", "testing"

    # Database
    DB_DRIVER: str = "psycopg2"
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    TEST_MODE: bool = False
    TEST_POSTGRES_DB: str = ""
    DATABASE_URL: Optional[PostgresDsn] = None

    # Nova flag de debug
    DEBUG: bool = False

    # Auth
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_USER_EXPIRE_MINUTOS: int
    ACCESS_TOKEN_CLIENT_EXPIRE_DIAS: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    # CORS and CSRF Protection
    BASE_URL: str = "http://localhost:8000"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]
    CORS_ORIGINS: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]
    CSRF_EXEMPT_ROUTES: List[str] = ["/user/login", "/user/register", "/docs", "/redoc", "/openapi.json"]

    # API Documentation
    SCHEMA_VISIBILITY: bool = False

    @field_validator("DATABASE_URL", mode="before")
    def assemble_db_url(cls, value, info):
        if value:
            return value

        data = info.data
        db_name = data.get("TEST_POSTGRES_DB") if data.get("TEST_MODE") else data.get("POSTGRES_DB")
        return PostgresDsn.build(
            scheme=f"postgresql+{data.get('DB_DRIVER', 'psycopg2')}",
            username=data["POSTGRES_USER"],
            password=data["POSTGRES_PASSWORD"],
            host=data["POSTGRES_HOST"],
            port=data["POSTGRES_PORT"],
            path=db_name,
        )

    @field_validator("CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """
        Se vier como string CSV (ex: 'a,b,c'), transforma em lista.
        Se vier já como lista ou JSON, retorna como está.
        """
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return v
        raise ValueError(f"CORS_ORIGINS inválido: {v!r}")

    @field_validator("LOG_LEVEL", mode="before")
    def validate_log_level(cls, v: str) -> str:
        """Garante que o valor é um nível válido do logging"""
        lvl = v.upper()
        getLevelName(lvl)  # valida
        return lvl

    model_config = ConfigDict(env_file=".env")


settings = Settings()
