"""
Feature extraction utilities for ML models
"""
from typing import Dict, List, Any, Tuple
from datetime import datetime
import hashlib
import re
from user_agents import parse
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from session and history data"""
    
    def __init__(self):
        self.browser_fingerprint_fields = [
            'screenResolution', 'timezone', 'platform', 'webglRenderer',
            'hardwareConcurrency', 'deviceMemory', 'touchSupport'
        ]
    
    def extract_session_features(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all features from a session"""
        features = {
            'ip_features': self._extract_ip_features(session.get('ip', '')),
            'temporal_features': self._extract_temporal_features(session.get('timestamp', 0)),
            'ua_features': self._extract_ua_features(session.get('userAgent', '')),
            'browser_features': self._extract_browser_features(session),
            'fingerprint': self._create_fingerprint(session)
        }
        
        return features
    
    def _extract_ip_features(self, ip: str) -> Dict[str, Any]:
        """Extract IP-related features"""
        features = {
            'ip': ip,
            'octets': [],
            'is_ipv6': False,
            'numeric_value': 0
        }
        
        try:
            if ':' in ip:  # IPv6
                features['is_ipv6'] = True
            else:  # IPv4
                octets = ip.split('.')
                features['octets'] = [int(o) for o in octets]
                # Convert to numeric for distance calculations
                features['numeric_value'] = sum(int(octets[i]) << (8 * (3 - i)) 
                                              for i in range(4))
        except:
            pass
        
        return features
    
    def _extract_temporal_features(self, timestamp: int) -> Dict[str, Any]:
        """Extract time-based features"""
        try:
            dt = datetime.fromtimestamp(timestamp / 1000)  # From milliseconds
            
            return {
                'hour': dt.hour,
                'day_of_week': dt.weekday(),
                'day_of_month': dt.day,
                'month': dt.month,
                'year': dt.year,
                'is_weekend': dt.weekday() >= 5,
                'is_business_hours': 9 <= dt.hour <= 17,
                'is_night': dt.hour >= 22 or dt.hour <= 6,
                'timestamp': timestamp
            }
        except:
            return {
                'hour': 0, 'day_of_week': 0, 'day_of_month': 1,
                'month': 1, 'year': 2024, 'is_weekend': False,
                'is_business_hours': False, 'is_night': False,
                'timestamp': timestamp
            }
    
    def _extract_ua_features(self, user_agent: str) -> Dict[str, Any]:
        """Extract UserAgent features"""
        features = {
            'raw': user_agent,
            'length': len(user_agent),
            'browser_family': 'Unknown',
            'browser_version': '',
            'os_family': 'Unknown',
            'os_version': '',
            'device_type': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': False,
            'is_bot': False
        }
        
        try:
            ua = parse(user_agent)
            
            features.update({
                'browser_family': ua.browser.family,
                'browser_version': ua.browser.version_string,
                'os_family': ua.os.family,
                'os_version': ua.os.version_string,
                'device_type': ua.device.family,
                'is_mobile': ua.is_mobile,
                'is_tablet': ua.is_tablet,
                'is_pc': ua.is_pc,
                'is_bot': ua.is_bot
            })
            
            # Check for suspicious patterns
            ua_lower = user_agent.lower()
            suspicious_patterns = [
                'headless', 'phantom', 'selenium', 'puppeteer',
                'scraper', 'crawler', 'bot', 'spider'
            ]
            
            features['suspicious_pattern_count'] = sum(
                1 for pattern in suspicious_patterns if pattern in ua_lower
            )
            
        except:
            pass
        
        return features
    
    def _extract_browser_features(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Extract browser fingerprinting features"""
        features = {}
        
        # Screen resolution
        resolution = session.get('screenResolution', '')
        if resolution:
            try:
                width, height = map(int, resolution.split('x'))
                features['screen_width'] = width
                features['screen_height'] = height
                features['screen_ratio'] = width / height if height > 0 else 0
            except:
                features['screen_width'] = 0
                features['screen_height'] = 0
                features['screen_ratio'] = 0
        
        # Hardware features
        features['hardware_concurrency'] = session.get('hardwareConcurrency', 0)
        features['device_memory'] = session.get('deviceMemory', 0)
        features['touch_support'] = session.get('touchSupport', False)
        
        # Browser capabilities
        features['cookie_enabled'] = session.get('isCookieEnabled', True)
        features['java_enabled'] = session.get('isJavaEnabled', False)
        
        # Plugins and fonts
        features['plugin_count'] = len(session.get('plugins', []))
        features['font_count'] = len(session.get('fonts', []))
        
        # Timezone
        features['timezone'] = session.get('timezone', '')
        
        # Platform
        features['platform'] = session.get('platform', '')
        
        # WebGL
        features['webgl_renderer'] = session.get('webglRenderer', '')
        
        return features
    
    def _create_fingerprint(self, session: Dict[str, Any]) -> str:
        """Create a browser fingerprint hash"""
        fingerprint_data = []
        
        for field in self.browser_fingerprint_fields:
            value = session.get(field, '')
            fingerprint_data.append(str(value))
        
        # Add canvas and audio fingerprints if available
        if session.get('canvasFingerprint'):
            fingerprint_data.append(session['canvasFingerprint'])
        
        if session.get('audioFingerprint'):
            fingerprint_data.append(session['audioFingerprint'])
        
        # Create hash
        fingerprint_string = '|'.join(fingerprint_data)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    def calculate_session_similarity(self, session1: Dict[str, Any], 
                                   session2: Dict[str, Any]) -> float:
        """Calculate similarity between two sessions (0-1)"""
        similarity_scores = []
        
        # UserAgent similarity
        if session1.get('userAgent') == session2.get('userAgent'):
            similarity_scores.append(1.0)
        else:
            # Partial similarity based on browser and OS
            ua1 = self._extract_ua_features(session1.get('userAgent', ''))
            ua2 = self._extract_ua_features(session2.get('userAgent', ''))
            
            ua_sim = 0.0
            if ua1['browser_family'] == ua2['browser_family']:
                ua_sim += 0.5
            if ua1['os_family'] == ua2['os_family']:
                ua_sim += 0.5
            
            similarity_scores.append(ua_sim)
        
        # Browser fingerprint similarity
        fp1 = self._create_fingerprint(session1)
        fp2 = self._create_fingerprint(session2)
        similarity_scores.append(1.0 if fp1 == fp2 else 0.0)
        
        # Platform similarity
        if session1.get('platform') == session2.get('platform'):
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Screen resolution similarity
        if session1.get('screenResolution') == session2.get('screenResolution'):
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        return sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0