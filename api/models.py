"""
Pydantic models for request/response validation
"""
from typing import List, Optional, Dict
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime


class Location(BaseModel):
    country: str
    city: str
    latitude: float
    longitude: float


class LoginHistoryItem(BaseModel):
    ip: str
    userAgent: str
    timestamp: int  # Unix milliseconds
    location: Location
    loginStatus: str
    
    @validator('loginStatus')
    def validate_login_status(cls, v):
        if v not in ['success', 'failure']:
            raise ValueError('loginStatus must be either "success" or "failure"')
        return v


class CurrentSession(BaseModel):
    ip: str
    userAgent: str
    timestamp: int  # Unix milliseconds
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


class AnalyzeRequest(BaseModel):
    currentSession: CurrentSession
    loginHistory: List[LoginHistoryItem] = []
    userId: EmailStr
    
    @validator('loginHistory')
    def validate_history_length(cls, v):
        if len(v) > 1000:  # Prevent excessive memory usage
            raise ValueError('loginHistory cannot exceed 1000 items')
        return v


class RiskScores(BaseModel):
    ip: int = Field(ge=0, le=100)
    datetime: int = Field(ge=0, le=100)
    userAgent: int = Field(ge=0, le=100)
    geolocation: int = Field(ge=0, le=100)
    overall: int = Field(ge=0, le=100)


class ResponseMeta(BaseModel):
    requestId: str
    userId: str
    timestamp: int
    processingTime: int  # milliseconds
    modelsVersion: str


class AnalyzeResponse(BaseModel):
    meta: ResponseMeta
    scores: RiskScores


class HealthResponse(BaseModel):
    status: str
    timestamp: int
    version: str
    models_loaded: bool
    redis_connected: bool
    mongodb_connected: bool


class ErrorResponse(BaseModel):
    error: str
    message: str
    timestamp: int
    request_id: Optional[str] = None