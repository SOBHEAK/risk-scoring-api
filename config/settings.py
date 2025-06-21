"""
Configuration settings for Xayone Risk Scoring API
"""
import os
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Xayone Risk Scoring API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    API_KEY_HEADER: str = "X-API-Key"
    # REMOVED ALLOWED_API_KEYS - No authentication for now
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60  # seconds
    
    # Database
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "xayone_risk_scoring"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_CACHE_TTL: int = 300  # 5 minutes
    
    # Model Settings
    MODELS_PATH: str = "./ml_models/trained_models"
    MODELS_VERSION: str = "v1.0.0"
    
    # Performance
    MAX_WORKERS: int = Field(default_factory=lambda: os.cpu_count() or 4)
    REQUEST_TIMEOUT: int = 30  # seconds
    
    # Risk Score Weights
    IP_WEIGHT: float = 0.30
    DATETIME_WEIGHT: float = 0.20
    USERAGENT_WEIGHT: float = 0.25
    GEOLOCATION_WEIGHT: float = 0.25
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # IP Analysis
    MAXMIND_LICENSE_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    
    # Geolocation
    MAX_TRAVEL_SPEED_KMH: float = 900.0  # Max feasible travel speed
    
    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()