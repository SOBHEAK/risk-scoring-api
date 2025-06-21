"""
DateTime Risk Model using Isolation Forest
Detects: Unusual login times, brute force patterns, timing attacks
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List
from datetime import datetime
import logging

from ml_models.base_model import BaseRiskModel

logger = logging.getLogger(__name__)


class DateTimeRiskModel(BaseRiskModel):
    """Isolation Forest model for temporal anomaly detection"""
    
    def __init__(self, model_path: str = None):
        super().__init__("DateTime Risk Model", model_path)
        self.scaler = StandardScaler()
        
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract temporal features"""
        timestamp = data.get('timestamp', 0)
        login_history = data.get('login_history', [])
        
        features = []
        
        try:
            # Convert to datetime
            dt = datetime.fromtimestamp(timestamp / 1000)  # From milliseconds
            
            # Time-based features
            features.append(dt.hour)  # Hour of day (0-23)
            features.append(dt.weekday())  # Day of week (0-6)
            features.append(dt.day)  # Day of month (1-31)
            features.append(dt.month)  # Month (1-12)
            
            # Is weekend
            features.append(1 if dt.weekday() >= 5 else 0)
            
            # Is business hours (9-17)
            features.append(1 if 9 <= dt.hour <= 17 else 0)
            
            # Is night time (22-6)
            features.append(1 if dt.hour >= 22 or dt.hour <= 6 else 0)
            
            # History-based features
            if login_history:
                # Time since last login (in hours)
                last_login = max(login_history, key=lambda x: x['timestamp'])
                time_diff = (timestamp - last_login['timestamp']) / 3600000  # to hours
                features.append(min(time_diff, 720))  # Cap at 30 days
                
                # Average time between logins
                if len(login_history) > 1:
                    sorted_history = sorted(login_history, key=lambda x: x['timestamp'])
                    time_diffs = []
                    for i in range(1, len(sorted_history)):
                        diff = (sorted_history[i]['timestamp'] - 
                               sorted_history[i-1]['timestamp']) / 3600000
                        time_diffs.append(diff)
                    avg_diff = np.mean(time_diffs) if time_diffs else 24
                    features.append(min(avg_diff, 720))
                else:
                    features.append(24)  # Default 24 hours
                
                # Login frequency in last 24 hours
                recent_logins = sum(1 for item in login_history 
                                  if timestamp - item['timestamp'] < 86400000)
                features.append(recent_logins)
                
                # Login frequency in last hour
                very_recent = sum(1 for item in login_history 
                                if timestamp - item['timestamp'] < 3600000)
                features.append(very_recent)
                
                # Usual login hours pattern
                login_hours = [datetime.fromtimestamp(item['timestamp']/1000).hour 
                             for item in login_history[-20:]]  # Last 20 logins
                if login_hours:
                    usual_hour = int(np.median(login_hours))
                    hour_deviation = abs(dt.hour - usual_hour)
                    features.append(min(hour_deviation, 12))
                else:
                    features.append(0)
                
                # Failed login attempts in last hour
                recent_failures = sum(1 for item in login_history 
                                    if timestamp - item['timestamp'] < 3600000 
                                    and item.get('loginStatus') == 'failure')
                features.append(recent_failures)
                
            else:
                # Default values when no history
                features.extend([24, 24, 0, 0, 0, 0])
                
        except Exception as e:
            logger.error(f"Error extracting datetime features: {e}")
            features = [0] * 13
            
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """Train the Isolation Forest on normal login patterns"""
        logger.info("Training DateTime Risk Model...")
        
        # Extract features
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features[0])
        
        X = np.array(X)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.05,  # Expected fraction of anomalies
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            verbose=1
        )
        self.model.fit(X_scaled)
        
        logger.info(f"DateTime model trained on {len(X)} samples")
    
    def predict_risk(self, current_session: Dict[str, Any], 
                    login_history: List[Dict[str, Any]] = None) -> int:
        """Predict risk score for current datetime"""
        if not self.is_loaded and self.model is None:
            logger.warning("Model not loaded, returning default score")
            return 50
        
        try:
            # Prepare data
            data = {
                'timestamp': current_session.get('timestamp', 0),
                'login_history': login_history or []
            }
            
            # Extract features
            features = self.extract_features(data)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and anomaly score
            prediction = self.model.predict(features_scaled)[0]
            anomaly_score = self.model.score_samples(features_scaled)[0]
            
            # Base risk calculation
            if prediction == 1:  # Normal
                base_risk = int(15 - anomaly_score * 15)
            else:  # Anomaly
                base_risk = int(50 - anomaly_score * 30)
            
            base_risk = max(0, min(100, base_risk))
            
            # Additional risk factors
            dt = datetime.fromtimestamp(current_session['timestamp'] / 1000)
            
            # Night time login (2-5 AM)
            if 2 <= dt.hour <= 5:
                base_risk = min(100, base_risk + 20)
            
            # Rapid succession logins (potential brute force)
            if login_history:
                recent_count = sum(1 for item in login_history 
                                 if current_session['timestamp'] - item['timestamp'] < 300000)  # 5 min
                if recent_count > 5:
                    base_risk = min(100, base_risk + 30)
                elif recent_count > 3:
                    base_risk = min(100, base_risk + 15)
                
                # Failed attempts
                recent_failures = sum(1 for item in login_history[-10:] 
                                    if item.get('loginStatus') == 'failure')
                if recent_failures > 3:
                    base_risk = min(100, base_risk + 20)
            
            # Check for timing attack patterns
            if login_history and len(login_history) > 5:
                # Check if logins are at exact intervals (bot behavior)
                recent = sorted(login_history[-6:], key=lambda x: x['timestamp'])
                intervals = []
                for i in range(1, len(recent)):
                    intervals.append(recent[i]['timestamp'] - recent[i-1]['timestamp'])
                
                if len(set(intervals)) == 1:  # All intervals are same
                    base_risk = min(100, base_risk + 25)
            
            return base_risk
            
        except Exception as e:
            logger.error(f"Error in datetime risk prediction: {e}")
            return 50