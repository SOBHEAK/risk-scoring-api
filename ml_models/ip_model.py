"""
IP Risk Model using One-Class SVM
Detects: VPNs, proxies, Tor, datacenter IPs, blacklisted IPs
"""
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List
import ipaddress
import logging
from .base_model import BaseRiskModel

logger = logging.getLogger(__name__)


class IPRiskModel(BaseRiskModel):
    """One-Class SVM model for IP risk detection"""
    
    def __init__(self, model_path: str = None):
        super().__init__("IP Risk Model", model_path)
        self.scaler = StandardScaler()
        self.known_vpn_asns = {
            13335,  # Cloudflare
            16509,  # Amazon AWS
            15169,  # Google
            8075,   # Microsoft Azure
            14061,  # DigitalOcean
            20473,  # Vultr
            63949,  # Linode
        }
        self.known_bad_ips = set()  # Will be populated from threat feeds
        
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract IP-based features"""
        ip = data.get('ip', '')
        features = []
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Basic IP features
            features.append(1 if ip_obj.is_private else 0)
            features.append(1 if ip_obj.is_loopback else 0)
            features.append(1 if ip_obj.is_multicast else 0)
            features.append(1 if ip_obj.is_reserved else 0)
            
            # IP version
            features.append(1 if ip_obj.version == 6 else 0)
            
            # Check if it's a known datacenter IP (simplified)
            octets = str(ip_obj).split('.')
            if ip_obj.version == 4:
                # Common datacenter ranges (simplified check)
                is_datacenter = (
                    octets[0] in ['104', '172', '192'] or
                    (octets[0] == '10' and not ip_obj.is_private)
                )
                features.append(1 if is_datacenter else 0)
            else:
                features.append(0)
            
            # Geographic diversity from history
            if 'login_history' in data:
                unique_ips = set(item['ip'] for item in data['login_history'])
                features.append(len(unique_ips))
                
                # Check if current IP was seen before
                features.append(1 if ip in unique_ips else 0)
            else:
                features.append(0)
                features.append(0)
            
            # Reputation score (placeholder - would use real threat intelligence)
            features.append(1 if ip in self.known_bad_ips else 0)
            
            # Time-based features
            if 'login_history' in data:
                # Number of different IPs used in last 24 hours
                recent_ips = set()
                current_time = data.get('timestamp', 0)
                for item in data['login_history']:
                    if current_time - item['timestamp'] < 86400000:  # 24 hours
                        recent_ips.add(item['ip'])
                features.append(len(recent_ips))
            else:
                features.append(0)
                
        except Exception as e:
            logger.error(f"Error extracting IP features: {e}")
            # Return default features on error
            features = [0] * 10
            
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """Train the One-Class SVM on legitimate IP data"""
        logger.info("Training IP Risk Model...")
        
        # Extract features from training data
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features[0])
        
        X = np.array(X)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train One-Class SVM
        self.model = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.05,  # Expected fraction of outliers
            verbose=True
        )
        self.model.fit(X_scaled)
        
        logger.info(f"IP model trained on {len(X)} samples")
    
    def predict_risk(self, current_session: Dict[str, Any], 
                    login_history: List[Dict[str, Any]] = None) -> int:
        """Predict risk score for current IP"""
        if not self.is_loaded and self.model is None:
            logger.warning("Model not loaded, returning default score")
            return 50
        
        try:
            # Prepare data
            data = {
                'ip': current_session.get('ip', ''),
                'timestamp': current_session.get('timestamp', 0),
                'login_history': login_history or []
            }
            
            # Extract features
            features = self.extract_features(data)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and decision score
            prediction = self.model.predict(features_scaled)[0]
            decision_score = self.model.decision_function(features_scaled)[0]
            
            # Check known bad IPs
            if data['ip'] in self.known_bad_ips:
                return 90
            
            # Check if IP is in VPN/datacenter range
            try:
                ip_obj = ipaddress.ip_address(data['ip'])
                if not ip_obj.is_private:
                    octets = str(ip_obj).split('.')
                    if octets[0] in ['104', '172']:  # Common VPN ranges
                        base_score = 70
                    else:
                        base_score = 0
                else:
                    base_score = 0
            except:
                base_score = 50
            
            # Convert SVM decision to risk score
            if prediction == 1:  # Inlier (normal)
                # Use decision score to fine-tune within normal range
                risk_score = max(0, min(30, int(30 - decision_score * 10)))
            else:  # Outlier (anomaly)
                # Use decision score to determine severity
                risk_score = max(31, min(100, int(70 - decision_score * 20)))
            
            # Combine with base score
            final_score = max(base_score, risk_score)
            
            # Additional checks
            if login_history:
                # If IP changed frequently recently
                recent_ips = set()
                current_time = current_session.get('timestamp', 0)
                for item in login_history[-10:]:  # Last 10 logins
                    if current_time - item['timestamp'] < 3600000:  # 1 hour
                        recent_ips.add(item['ip'])
                
                if len(recent_ips) > 3:
                    final_score = min(100, final_score + 20)
            
            return final_score
            
        except Exception as e:
            logger.error(f"Error in IP risk prediction: {e}")
            return 50  # Default medium risk on error