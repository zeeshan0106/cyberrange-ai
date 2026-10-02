from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, AliasChoices
from typing import Optional
from pathlib import Path

# Resolve path to backend .env
BACKEND_DIR = Path(__file__).resolve().parent
ROOT_ENV = BACKEND_DIR.parent / ".env"
BACKEND_ENV = BACKEND_DIR / ".env"

env_file_path = BACKEND_ENV if BACKEND_ENV.exists() else ROOT_ENV

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(env_file_path),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Database
    MONGO_URL: str = Field(default="mongodb://localhost:27017")
    DB_NAME: str = Field(default="cyberrange_db")
    CORS_ORIGINS: str = Field(default="http://localhost:3000")

    # LLM Provider Configuration
    # Uses validation_alias so LLM_API_KEY is checked first, then falls back to EMERGENT_LLM_KEY
    LLM_API_KEY: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "EMERGENT_LLM_KEY")
    )
    LLM_MODEL: str = Field(default="gemini/gemini-3.5-flash-lite")
    LLM_TIMEOUT: float = Field(default=25.0)
    LLM_MAX_RETRIES: int = Field(default=1)

settings = Settings()
