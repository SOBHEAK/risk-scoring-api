# ml_models/ip_model.py
import os
import joblib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional
from ml_models.base_model import BaseRiskModel
from utils.ip_utils import get_ip_risk_features, parse_ip_address


class IPRiskModel(BaseRiskModel):
    """
    IP Risk Model using One-Class SVM.
    Detects anomalous IP addresses (VPNs, proxies, Tor, datacenter IPs).
    """
    
    def __init__(self, version: str = "v1.0.0"):
        super().__init__("ip_risk_model", version)
        self.scaler = StandardScaler()
        self.feature_names = [
            'is_new_ip', 'is_datacenter', 'is_tor', 'is_private',
            'is_suspicious_type', 'historical_ip_count', 'ip_numeric_normalized',
            'is_ipv6', 'is_reserved', 'is_multicast'
        ]
    
    def extract_features(self, current_session: Dict, login_history: List[Dict]) -> np.ndarray:
        """Extract IP-related features."""
        current_ip = current_session['ip']
        historical_ips = [item['ip'] for item in login_history]
        
        # Get basic risk features
        features = get_ip_risk_features(current_ip, historical_ips)
        
        # Add additional features
        ip_info = parse_ip_address(current_ip)
        
        # Normalize IP numeric value
        if ip_info['version'] == 4:
            max_ipv4 = 2**32 - 1
            ip_numeric_normalized = ip_info['numeric_value'] / max_ipv4
        else:
            max_ipv6 = 2**128 - 1
            ip_numeric_normalized = ip_info['numeric_value'] / max_ipv6
        
        # Create feature vector
        feature_vector = [
            features['is_new_ip'],
            features['is_datacenter'],
            features['is_tor'],
            features['is_private'],
            features['is_suspicious_type'],
            min(features['historical_ip_count'] / 10, 1),  # Normalize
            ip_numeric_normalized,
            float(ip_info['version'] == 6),
            float(ip_info['is_reserved']),
            float(ip_info['is_multicast'])
        ]
        
        return np.array(feature_vector)
    
    def train(self, training_data: Dict) -> None:
        """
        Train the One-Class SVM model.
        
        Args:
            training_data: Dictionary with 'normal' and 'anomalous' IP data
        """
        # Extract features for normal IPs
        normal_features = []
        for ip_data in training_data['normal']:
            features = self.extract_features(
                {'ip': ip_data['ip']},
                ip_data.get('history', [])
            )
            normal_features.append(features)
        
        X_train = np.array(normal_features)
        
        # Fit scaler
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        
        # Train One-Class SVM
        self.model = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.1,  # Expected fraction of outliers
            shrinking=True,
            cache_size=200
        )
        
        self.model.fit(X_train_scaled)
        self.is_loaded = True
        
        print(f"IP Risk Model trained with {len(X_train)} samples")
    
    def predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Override predict to include scaling."""
        if not self.is_loaded:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Extract and scale features
        features = self.extract_features(current_session, login_history)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get decision function value
        decision_value = self.model.decision_function(features_scaled)[0]
        
        # Calculate base risk from SVM
        base_risk = self._normalize_score(-decision_value, method='svm')
        
        # Apply rules-based adjustments
        risk_adjustments = self._apply_risk_rules(current_session, login_history)
        
        # Combine base risk with adjustments
        final_risk = base_risk + risk_adjustments
        
        return max(0, min(100, final_risk))
    
    def _apply_risk_rules(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Apply additional risk rules based on IP characteristics."""
        adjustment = 0
        current_ip = current_session['ip']
        ip_features = get_ip_risk_features(current_ip, [item['ip'] for item in login_history])
        
        # High risk for certain IP types
        if ip_features['is_tor']:
            adjustment += 30  # Tor exit nodes are very high risk
        elif ip_features['is_datacenter']:
            adjustment += 20  # Datacenter IPs are suspicious
        
        # New IP from suspicious location
        if ip_features['is_new_ip'] and ip_features['is_suspicious_type']:
            adjustment += 15
        
        # Private IP (could indicate spoofing attempt)
        if ip_features['is_private']:
            adjustment += 10
        
        return adjustment
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save model and scaler."""
        # First save the base model
        super().save_model(path)
        
        # Also save the scaler
        scaler_path = (path or self.model_path).replace('.pkl', '_scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model and scaler."""
        # First load the base model
        if not super().load_model(path):
            return False
        
        # Also load the scaler
        scaler_path = (path or self.model_path).replace('.pkl', '_scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        else:
            print(f"Warning: Scaler file not found at {scaler_path}")
            self.scaler = StandardScaler()
        
        return True