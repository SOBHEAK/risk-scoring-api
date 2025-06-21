"""
Authentication module for API
Currently disabled for development
"""
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
from typing import Optional

from config.settings import settings

# API Key header (kept for future use)
api_key_header = APIKeyHeader(
    name=settings.API_KEY_HEADER,
    auto_error=False
)


async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Verify API key - Currently disabled for development
    Returns dummy value
    """
    # AUTHENTICATION DISABLED FOR NOW
    # Just return a dummy value
    return "no-auth-required"
    
    # When you want to enable it later, uncomment this:
    """
    if not api_key:
        raise HTTPException(
            status_code=403, 
            detail="Missing API Key"
        )
    
    if api_key not in settings.ALLOWED_API_KEYS:
        raise HTTPException(
            status_code=403, 
            detail="Invalid API Key"
        )
    
    return api_key
    """