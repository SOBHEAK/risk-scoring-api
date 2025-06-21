# api/models.py
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime


class CurrentSession(BaseModel):
    ip: str = Field(..., description="IP address of the current login attempt")
    userAgent: str = Field(..., description="User agent string")
    timestamp: int = Field(..., description="Unix timestamp in milliseconds")
    acceptLanguage: Optional[str] = None
    screenResolution: Optional[str] = None
    timezone: Optional[str] = None
    platform: Optional[str] = None
    webglRenderer: Optional[str] = None
    fonts: Optional[List[str]] = []
    canvasFingerprint: Optional[str] = None
    audioFingerprint: Optional[str] = None
    plugins: Optional[List[str]] = []
    touchSupport: Optional[bool] = None
    deviceMemory: Optional[int] = None
    hardwareConcurrency: Optional[int] = None
    referrer: Optional[str] = None
    isCookieEnabled: Optional[bool] = None
    isJavaEnabled: Optional[bool] = None
    browserVersion: Optional[str] = None
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v < 0:
            raise ValueError('Timestamp must be positive')
        # Check if timestamp is in milliseconds (13 digits for current timestamps)
        if len(str(v)) < 10:
            raise ValueError('Timestamp appears to be invalid')
        return v


class Location(BaseModel):
    country: str
    city: str
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)


class LoginHistoryItem(BaseModel):
    ip: str
    userAgent: str
    timestamp: int
    location: Location
    loginStatus: str = Field(..., pattern="^(success|failure)$")
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v < 0:
            raise ValueError('Timestamp must be positive')
        return v


class AnalyzeRequest(BaseModel):
    currentSession: CurrentSession
    loginHistory: List[LoginHistoryItem] = []
    userId: EmailStr
    
    class Config:
        json_schema_extra = {
            "example": {
                "currentSession": {
                    "ip": "192.168.1.1",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "timestamp": 1703001600000,
                    "timezone": "America/New_York",
                    "platform": "Win32"
                },
                "loginHistory": [
                    {
                        "ip": "192.168.1.1",
                        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "timestamp": 1702915200000,
                        "location": {
                            "country": "United States",
                            "city": "New York",
                            "latitude": 40.7128,
                            "longitude": -74.0060
                        },
                        "loginStatus": "success"
                    }
                ],
                "userId": "user@example.com"
            }
        }


class MetaResponse(BaseModel):
    requestId: str
    userId: str
    timestamp: int
    processingTime: int
    modelsVersion: str


class ScoresResponse(BaseModel):
    ip: int = Field(..., ge=0, le=100)
    datetime: int = Field(..., ge=0, le=100)
    userAgent: int = Field(..., ge=0, le=100)
    geolocation: int = Field(..., ge=0, le=100)
    overall: int = Field(..., ge=0, le=100)


class AnalyzeResponse(BaseModel):
    meta: MetaResponse
    scores: ScoresResponse
    
    class Config:
        json_schema_extra = {
            "example": {
                "meta": {
                    "requestId": "req_550e8400-e29b-41d4-a716-446655440000",
                    "userId": "user@example.com",
                    "timestamp": 1703001600000,
                    "processingTime": 145,
                    "modelsVersion": "v1.0.0"
                },
                "scores": {
                    "ip": 15,
                    "datetime": 10,
                    "userAgent": 5,
                    "geolocation": 20,
                    "overall": 13
                }
            }
        }


class HealthResponse(BaseModel):
    status: str
    timestamp: int
    version: str
    models_loaded: bool
    database_connected: bool
    redis_connected: bool