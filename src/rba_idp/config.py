"""Runtime settings (env / .env)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "rba-idp"
    host: str = "0.0.0.0"
    port: int = 8001

    database_url: str = "postgresql+psycopg://rba:rba@localhost:5432/rba_idp"
    # When true, use in-memory SQLite (unit tests / no Docker).
    use_memory_db: bool = False

    seed_user_id: str = "usr_demo"
    seed_email: str = "demo@example.com"
    seed_password: str = "demo-password"
    seed_application_id: str = "demo-banking-app"
    seed_application_name: str = "Demo banking app"


@lru_cache
def get_settings() -> Settings:
    return Settings()
