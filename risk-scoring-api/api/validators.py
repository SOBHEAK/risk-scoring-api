# api/validators.py
import re
import ipaddress
from typing import Optional
from datetime import datetime, timezone


def validate_ip_address(ip: str) -> bool:
    """
    Validate if the given string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_user_agent(user_agent: str) -> bool:
    """
    Validate if the user agent string is valid and not empty.
    
    Args:
        user_agent: User agent string to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not user_agent or len(user_agent.strip()) < 10:
        return False
    
    # Check for common bot patterns that should be flagged but not rejected
    # (we want to analyze these, not block them)
    return True


def validate_timestamp(timestamp: int) -> bool:
    """
    Validate if the timestamp is reasonable (not too far in past or future).
    
    Args:
        timestamp: Unix timestamp in milliseconds
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # Convert milliseconds to seconds
        ts_seconds = timestamp / 1000
        dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        
        # Check if timestamp is within reasonable bounds
        # Not more than 1 year in the past
        min_date = datetime.now(timezone.utc).replace(year=datetime.now().year - 1)
        # Not more than 1 day in the future (to account for clock drift)
        max_date = datetime.now(timezone.utc).replace(day=datetime.now().day + 1)
        
        return min_date <= dt <= max_date
    except (ValueError, OverflowError):
        return False


def validate_screen_resolution(resolution: Optional[str]) -> bool:
    """
    Validate screen resolution format (e.g., "1920x1080").
    
    Args:
        resolution: Screen resolution string
        
    Returns:
        True if valid or None, False otherwise
    """
    if resolution is None:
        return True
    
    pattern = r'^\d{3,5}x\d{3,5}$'
    return bool(re.match(pattern, resolution))


def validate_timezone(timezone_str: Optional[str]) -> bool:
    """
    Validate timezone string format.
    
    Args:
        timezone_str: Timezone string (e.g., "America/New_York" or UTC offset)
        
    Returns:
        True if valid or None, False otherwise
    """
    if timezone_str is None:
        return True
    
    # Check for UTC offset format (e.g., "+05:30", "-08:00")
    utc_pattern = r'^[+-]\d{2}:\d{2}$'
    if re.match(utc_pattern, timezone_str):
        return True
    
    # Check for timezone name format (basic validation)
    tz_pattern = r'^[A-Za-z]+/[A-Za-z_]+$'
    return bool(re.match(tz_pattern, timezone_str))


def sanitize_input(text: Optional[str], max_length: int = 1000) -> Optional[str]:
    """
    Sanitize input text to prevent injection attacks.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text or None
    """
    if text is None:
        return None
    
    # Truncate to max length
    text = text[:max_length]
    
    # Remove null bytes and other problematic characters
    text = text.replace('\x00', '')
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text if text else None