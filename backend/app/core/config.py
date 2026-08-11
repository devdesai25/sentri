import os
from typing import List, Optional, Union

from pydantic import AnyHttpUrl, PostgresDsn, validator, computed_field
from pydantic_settings import BaseSettings
from pydantic import field_validator
from app.schemas.command import RiskLevel



class Settings(BaseSettings):
    # API configuration
    PROJECT_NAME: str = "Sentri API"
    PROJECT_DESCRIPTION: str = "API for Sentri security & event monitoring system"
    PROJECT_VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # CORS configuration
    CORS_ORIGINS: List[Union[str, AnyHttpUrl]] = ["http://localhost:3000"]
    
    # PostgreSQL configuration
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "root")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "sentri")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", "5432")
    # DATABASE_URL: Optional[PostgresDsn] = None
    SQLALCHEMY_DATABASE_URI: Optional[str] = None

    OPENAI_API_KEY: str =""

    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_IDS: List[int] = []
    TELEGRAM_RISK_THRESHOLD: RiskLevel = RiskLevel.MEDIUM
    TELEGRAM_ENABLED: bool = True

    @computed_field
    @property
    def DATABASE_URL(self) -> str:
        """Build the database URL from component parts."""
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
    
    # Security configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "development_secret_key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Logging configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()