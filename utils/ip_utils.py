"""
IP analysis utilities
"""
import ipaddress
import asyncio
import aiohttp
from typing import Dict, Optional, Set
import logging

logger = logging.getLogger(__name__)


class IPAnalyzer:
    """Analyze IP addresses for risk factors"""
    
    def __init__(self):
        # Known VPN/Proxy providers (simplified list)
        self.vpn_ranges = {
            '104.16.0.0/12',    # Cloudflare
            '172.64.0.0/13',    # Cloudflare
            '162.158.0.0/15',   # Cloudflare
            '198.41.128.0/17',  # Cloudflare
            '13.32.0.0/15',     # AWS CloudFront
            '52.84.0.0/15',     # AWS CloudFront
            '54.182.0.0/16',    # AWS CloudFront
            '54.192.0.0/16',    # AWS CloudFront
        }
        
        # Convert to ip_network objects
        self.vpn_networks = [ipaddress.ip_network(range_) for range_ in self.vpn_ranges]
        
        # Known datacenter ASNs
        self.datacenter_asns = {
            13335,  # Cloudflare
            16509,  # Amazon AWS
            15169,  # Google
            8075,   # Microsoft Azure
            14061,  # DigitalOcean
            20473,  # Vultr
            63949,  # Linode
            16276,  # OVH
            24940,  # Hetzner
        }
        
    def is_vpn_or_proxy(self, ip: str) -> bool:
        """Check if IP is from known VPN/proxy range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for network in self.vpn_networks:
                if ip_obj in network:
                    return True
                    
            return False
        except:
            return False
    
    def is_datacenter_ip(self, ip: str) -> bool:
        """Check if IP is from a datacenter"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Simple heuristic for IPv4
            if ip_obj.version == 4:
                octets = str(ip_obj).split('.')
                
                # Common datacenter ranges
                if octets[0] in ['104', '172', '198', '162']:
                    return True
                    
                # AWS ranges
                if octets[0] in ['52', '54', '35', '13', '18']:
                    return True
                    
                # Google Cloud
                if octets[0] in ['34', '35', '104', '107']:
                    return True
                    
            return False
        except:
            return False
    
    def is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a known Tor exit node"""
        # In production, this would check against the Tor exit node list
        # For now, using a simple heuristic
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Some known Tor exit node ranges (simplified)
            tor_ranges = [
                '192.42.116.0/24',
                '199.87.154.0/24',
                '176.10.99.0/24',
            ]
            
            for range_ in tor_ranges:
                if ip_obj in ipaddress.ip_network(range_):
                    return True
                    
            return False
        except:
            return False
    
    async def check_ip_reputation(self, ip: str, api_key: str = None) -> Dict[str, any]:
        """Check IP reputation using external service"""
        # In production, this would use AbuseIPDB or similar
        # For now, returning mock data
        return {
            'is_blacklisted': False,
            'abuse_score': 0,
            'is_vpn': self.is_vpn_or_proxy(ip),
            'is_datacenter': self.is_datacenter_ip(ip),
            'is_tor': self.is_tor_exit_node(ip),
            'country': 'US',
            'risk_score': 0
        }
    
    def analyze_ip_behavior(self, ip: str, ip_history: Set[str]) -> Dict[str, any]:
        """Analyze IP behavior patterns"""
        analysis = {
            'is_new_ip': ip not in ip_history,
            'ip_diversity': len(ip_history),
            'is_suspicious_range': False,
            'is_private': False,
            'is_loopback': False
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            analysis['is_private'] = ip_obj.is_private
            analysis['is_loopback'] = ip_obj.is_loopback
            
            # Check for suspicious patterns
            if ip_obj.version == 4:
                octets = str(ip_obj).split('.')
                
                # Rapid IP changes in same subnet might indicate proxy rotation
                subnet_changes = 0
                for hist_ip in ip_history:
                    try:
                        hist_octets = hist_ip.split('.')
                        if hist_octets[:3] == octets[:3]:  # Same /24 subnet
                            subnet_changes += 1
                    except:
                        pass
                
                if subnet_changes > 5:
                    analysis['is_suspicious_range'] = True
                    
        except:
            pass
            
        return analysis