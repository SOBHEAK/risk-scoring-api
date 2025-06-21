# utils/feature_extractors.py
import math
import re
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from user_agents import parse as parse_user_agent


def extract_user_agent_features(user_agent: str) -> Dict[str, any]:
    """
    Extract features from user agent string.
    
    Args:
        user_agent: User agent string
        
    Returns:
        Dictionary of extracted features
    """
    features = {
        'length': len(user_agent),
        'is_bot': False,
        'is_mobile': False,
        'is_tablet': False,
        'is_pc': False,
        'browser_family': 'unknown',
        'browser_version': 'unknown',
        'os_family': 'unknown',
        'os_version': 'unknown',
        'device_family': 'unknown',
        'is_suspicious': False,
        'entropy': calculate_entropy(user_agent),
    }
    
    # Check for bot patterns
    bot_patterns = [
        r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
        r'python', r'java', r'ruby', r'perl', r'php', r'node',
        r'headless', r'phantom', r'selenium', r'puppeteer'
    ]
    
    ua_lower = user_agent.lower()
    for pattern in bot_patterns:
        if re.search(pattern, ua_lower):
            features['is_bot'] = True
            features['is_suspicious'] = True
            break
    
    # Try to parse user agent
    try:
        ua = parse_user_agent(user_agent)
        
        features['browser_family'] = ua.browser.family or 'unknown'
        features['browser_version'] = ua.browser.version_string or 'unknown'
        features['os_family'] = ua.os.family or 'unknown'
        features['os_version'] = ua.os.version_string or 'unknown'
        features['device_family'] = ua.device.family or 'unknown'
        
        features['is_mobile'] = ua.is_mobile
        features['is_tablet'] = ua.is_tablet
        features['is_pc'] = ua.is_pc
        
        # Check for suspicious combinations
        if features['browser_family'] == 'Other' or features['os_family'] == 'Other':
            features['is_suspicious'] = True
            
    except Exception:
        features['is_suspicious'] = True
    
    return features


def extract_datetime_features(timestamp: int, history_timestamps: List[int]) -> Dict[str, float]:
    """
    Extract datetime-related features.
    
    Args:
        timestamp: Current timestamp in milliseconds
        history_timestamps: List of historical timestamps
        
    Returns:
        Dictionary of datetime features
    """
    dt = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
    
    features = {
        'hour': dt.hour,
        'day_of_week': dt.weekday(),  # 0 = Monday, 6 = Sunday
        'is_weekend': float(dt.weekday() >= 5),
        'is_business_hours': float(9 <= dt.hour <= 17),
        'is_night': float(dt.hour < 6 or dt.hour > 22),
        'time_since_last_login': 0.0,
        'login_velocity': 0.0,
        'is_burst_pattern': False,
    }
    
    if history_timestamps:
        # Sort timestamps
        sorted_history = sorted(history_timestamps)
        
        # Time since last login (in hours)
        last_login = sorted_history[-1]
        features['time_since_last_login'] = (timestamp - last_login) / (1000 * 60 * 60)
        
        # Calculate login velocity (logins per hour in last 24h)
        last_24h = timestamp - (24 * 60 * 60 * 1000)
        recent_logins = [ts for ts in sorted_history if ts > last_24h]
        if recent_logins:
            time_span_hours = (timestamp - recent_logins[0]) / (1000 * 60 * 60)
            if time_span_hours > 0:
                features['login_velocity'] = len(recent_logins) / time_span_hours
        
        # Check for burst pattern (multiple logins in short time)
        last_hour = timestamp - (60 * 60 * 1000)
        recent_hour_logins = [ts for ts in sorted_history if ts > last_hour]
        features['is_burst_pattern'] = len(recent_hour_logins) > 5
    
    return features


def extract_fingerprint_features(session_data: Dict) -> Dict[str, any]:
    """
    Extract features from browser fingerprint data.
    
    Args:
        session_data: Session data containing fingerprint information
        
    Returns:
        Dictionary of fingerprint features
    """
    features = {
        'has_canvas_fp': bool(session_data.get('canvasFingerprint')),
        'has_audio_fp': bool(session_data.get('audioFingerprint')),
        'has_webgl': bool(session_data.get('webglRenderer')),
        'font_count': len(session_data.get('fonts', [])),
        'plugin_count': len(session_data.get('plugins', [])),
        'touch_support': session_data.get('touchSupport', False),
        'cookie_enabled': session_data.get('isCookieEnabled', True),
        'java_enabled': session_data.get('isJavaEnabled', False),
        'fingerprint_completeness': 0.0,
        'is_suspicious_config': False,
    }
    
    # Calculate fingerprint completeness
    optional_fields = [
        'screenResolution', 'timezone', 'platform', 'webglRenderer',
        'canvasFingerprint', 'audioFingerprint', 'deviceMemory',
        'hardwareConcurrency', 'browserVersion'
    ]
    
    present_fields = sum(1 for field in optional_fields if session_data.get(field) is not None)
    features['fingerprint_completeness'] = present_fields / len(optional_fields)
    
    # Check for suspicious configurations
    if features['java_enabled']:  # Java is rarely enabled in modern browsers
        features['is_suspicious_config'] = True
    
    if features['plugin_count'] > 10:  # Unusually high plugin count
        features['is_suspicious_config'] = True
    
    if not features['cookie_enabled']:  # Cookies disabled is unusual
        features['is_suspicious_config'] = True
    
    # Check screen resolution
    if session_data.get('screenResolution'):
        res_match = re.match(r'^(\d+)x(\d+)$', session_data['screenResolution'])
        if res_match:
            width, height = int(res_match.group(1)), int(res_match.group(2))
            # Check for headless browser resolutions
            if (width, height) in [(1920, 1080), (1366, 768), (1024, 768)]:
                if not features['touch_support'] and features['plugin_count'] == 0:
                    features['is_suspicious_config'] = True
    
    return features


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Args:
        text: Input string
        
    Returns:
        Entropy value
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_len = len(text)
    
    for count in char_counts.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def hash_feature(value: str) -> str:
    """
    Create a hash of a feature value for consistency checking.
    
    Args:
        value: Feature value to hash
        
    Returns:
        SHA256 hash hex string
    """
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def extract_all_features(current_session: Dict, login_history: List[Dict]) -> Dict[str, any]:
    """
    Extract all features for risk scoring.
    
    Args:
        current_session: Current session data
        login_history: User's login history
        
    Returns:
        Complete feature dictionary
    """
    # Extract basic features
    features = {}
    
    # User agent features
    ua_features = extract_user_agent_features(current_session['userAgent'])
    features.update({f'ua_{k}': v for k, v in ua_features.items()})
    
    # Datetime features
    history_timestamps = [item['timestamp'] for item in login_history]
    dt_features = extract_datetime_features(current_session['timestamp'], history_timestamps)
    features.update({f'dt_{k}': v for k, v in dt_features.items()})
    
    # Fingerprint features
    fp_features = extract_fingerprint_features(current_session)
    features.update({f'fp_{k}': v for k, v in fp_features.items()})
    
    # IP features (delegated to ip_utils)
    from utils.ip_utils import get_ip_risk_features
    historical_ips = [item['ip'] for item in login_history]
    ip_features = get_ip_risk_features(current_session['ip'], historical_ips)
    features.update({f'ip_{k}': v for k, v in ip_features.items()})
    
    return features