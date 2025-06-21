"""
Input validation utilities
"""
import ipaddress
from typing import Dict, Any
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_timestamp(timestamp: int) -> bool:
    """Validate timestamp is reasonable"""
    try:
        # Check if timestamp is in milliseconds and within reasonable range
        # Between year 2020 and 2030
        min_ts = 1577836800000  # Jan 1, 2020
        max_ts = 1893456000000  # Jan 1, 2030
        
        return min_ts <= timestamp <= max_ts
    except:
        return False


def validate_user_agent(user_agent: str) -> bool:
    """Validate user agent string"""
    if not user_agent or len(user_agent) < 10:
        return False
    
    # Check for basic structure
    if not any(browser in user_agent for browser in ['Mozilla', 'Chrome', 'Safari', 'Firefox', 'Edge', 'Opera']):
        # Allow bots and crawlers too
        if not any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']):
            return False
    
    return True


def validate_location(location: Dict[str, Any]) -> bool:
    """Validate location data"""
    try:
        lat = location.get('latitude')
        lon = location.get('longitude')
        
        if lat is None or lon is None:
            return False
        
        # Valid latitude: -90 to 90
        # Valid longitude: -180 to 180
        if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return False
        
        # Check required fields
        if not location.get('country') or not location.get('city'):
            return False
        
        return True
    except:
        return False


def sanitize_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize input data to prevent injection attacks"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Remove potential script tags and SQL injection attempts
        data = re.sub(r'<script[^>]*>.*?</script>', '', data, flags=re.IGNORECASE)
        data = re.sub(r'(DROP|DELETE|INSERT|UPDATE|SELECT)\s+(TABLE|FROM|INTO)', '', data, flags=re.IGNORECASE)
        return data.strip()
    else:
        return data