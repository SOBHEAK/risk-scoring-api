# config/settings.py
import os
from typing import List
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Configuration
    api_title: str = "Xayone Risk Scoring API"
    api_version: str = "1.0.0"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    
    # Security
    api_keys: List[str] = []
    secret_key: str = "change-this-in-production"
    
    # Database
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "xayone_risk_scoring"
    mongodb_max_pool_size: int = 10
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    redis_cache_ttl: int = 300  # 5 minutes
    
    # ML Models
    models_path: str = "./models"
    model_version: str = "v1.0.0"
    
    # Performance
    max_requests_per_minute: int = 100
    request_timeout: int = 30
    worker_count: int = 4
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    class Config:
        env_file = ".env"
        
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Parse comma-separated API keys
        if isinstance(self.api_keys, str):
            self.api_keys = [key.strip() for key in self.api_keys.split(",") if key.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()