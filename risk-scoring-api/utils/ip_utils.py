# utils/ip_utils.py
import ipaddress
import re
from typing import Dict, Tuple, Optional


def parse_ip_address(ip: str) -> Dict[str, any]:
    """
    Parse IP address and extract relevant features.
    
    Args:
        ip: IP address string
        
    Returns:
        Dictionary with IP features
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        return {
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_global': ip_obj.is_global,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'numeric_value': int(ip_obj),
            'ip_type': classify_ip_type(ip)
        }
    except ValueError:
        return {
            'version': 0,
            'is_private': False,
            'is_global': False,
            'is_loopback': False,
            'is_multicast': False,
            'is_reserved': False,
            'numeric_value': 0,
            'ip_type': 'invalid'
        }


def classify_ip_type(ip: str) -> str:
    """
    Classify IP address type (residential, datacenter, vpn, etc.).
    
    Args:
        ip: IP address string
        
    Returns:
        IP type classification
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Private IP ranges
        if ip_obj.is_private:
            return 'private'
        
        # Loopback
        if ip_obj.is_loopback:
            return 'loopback'
        
        # Check for common VPN/proxy patterns
        if is_datacenter_ip(ip):
            return 'datacenter'
        
        # Check for Tor exit nodes (simplified check)
        if is_tor_exit_node(ip):
            return 'tor'
        
        # Default to residential for public IPs
        return 'residential'
        
    except ValueError:
        return 'invalid'


def is_datacenter_ip(ip: str) -> bool:
    """
    Check if IP belongs to known datacenter ranges.
    
    Args:
        ip: IP address string
        
    Returns:
        True if datacenter IP, False otherwise
    """
    # Common datacenter IP ranges (simplified for demonstration)
    datacenter_ranges = [
        '104.16.0.0/12',      # Cloudflare
        '172.64.0.0/13',      # Cloudflare
        '162.158.0.0/15',     # Cloudflare
        '198.41.128.0/17',    # Cloudflare
        '35.180.0.0/12',      # AWS
        '52.0.0.0/6',         # AWS
        '34.64.0.0/10',       # Google Cloud
        '35.184.0.0/13',      # Google Cloud
        '40.112.0.0/13',      # Azure
        '65.52.0.0/14',       # Azure
    ]
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in datacenter_ranges:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except ValueError:
        pass
    
    return False


def is_tor_exit_node(ip: str) -> bool:
    """
    Check if IP is a known Tor exit node.
    
    Args:
        ip: IP address string
        
    Returns:
        True if Tor exit node, False otherwise
    """
    # In production, this would check against a real Tor exit node list
    # For now, we'll use a simple pattern check
    tor_patterns = [
        r'^198\.96\.',
        r'^199\.87\.',
        r'^176\.10\.',
        r'^46\.165\.',
    ]
    
    for pattern in tor_patterns:
        if re.match(pattern, ip):
            return True
    
    return False


def get_ip_risk_features(ip: str, historical_ips: list) -> Dict[str, float]:
    """
    Extract risk-related features from IP address.
    
    Args:
        ip: Current IP address
        historical_ips: List of historical IP addresses for the user
        
    Returns:
        Dictionary of risk features
    """
    features = parse_ip_address(ip)
    
    # Add risk indicators
    risk_features = {
        'is_new_ip': float(ip not in historical_ips),
        'is_datacenter': float(features['ip_type'] == 'datacenter'),
        'is_tor': float(features['ip_type'] == 'tor'),
        'is_private': float(features['is_private']),
        'is_suspicious_type': float(features['ip_type'] in ['datacenter', 'tor', 'vpn']),
        'historical_ip_count': len(set(historical_ips)),
    }
    
    return risk_features


def calculate_ip_distance(ip1: str, ip2: str) -> Optional[int]:
    """
    Calculate the numerical distance between two IP addresses.
    
    Args:
        ip1: First IP address
        ip2: Second IP address
        
    Returns:
        Numerical distance or None if invalid
    """
    try:
        addr1 = ipaddress.ip_address(ip1)
        addr2 = ipaddress.ip_address(ip2)
        
        if addr1.version != addr2.version:
            return None
        
        return abs(int(addr1) - int(addr2))
    except ValueError:
        return None