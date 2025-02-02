from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from typing import List, Dict

load_dotenv()

class Settings(BaseSettings):
    # Base
    ENV: str = "development"
    DEBUG: bool = True
    PROJECT_NAME: str = "GuardAIS API"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "your-secret-key-here"  # Cambiar en producción
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 horas
    OTX_API_KEY: str = "your-otx-key-here"
    VIRUSTOTAL_API_KEY: str
    # Añadir a la clase Settings
    GOOGLE_SAFEBROWSING_API_KEY: str
    OPENAI_API_KEY: str
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    # Añadir a la clase Settings
    THREATFOX_API_KEY: str
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./guardais.db"
    
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    
    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    
    # Limits
    MAX_SCAN_SIZE: int = 10 * 1024 * 1024  # 10MB
    SCAN_TIMEOUT: int = 300  # 5 minutos
    BASIC_USER_DAILY_LIMIT: int = 10
    ANALYST_USER_DAILY_LIMIT: int = 50
    ADMIN_USER_DAILY_LIMIT: int = 100
    
    # Security Settings
    ALLOWED_ROLES: List[str] = ["basic", "analyst", "admin"]
    CACHE_TTL: int = 3600
    MAX_HISTORY_LIMIT: int = 100
    BLOCKED_DOMAINS: List[str] = []
    
    # Service Weights
    SECURITY_SERVICE_WEIGHTS: Dict[str, float] = {
        "otx": 1.0
    }
    
    # Security Thresholds
    SECURITY_THRESHOLDS: Dict[str, int] = {
        "malicious": 70,
        "suspicious": 40
    }
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]
    
    # Flower
    FLOWER_PORT: int = 5555
    FLOWER_BASIC_AUTH: str = "admin:admin"  # Cambiar en producción

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
