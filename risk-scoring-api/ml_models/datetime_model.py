# ml_models/datetime_model.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional
from datetime import datetime, timezone
from ml_models.base_model import BaseRiskModel
from utils.feature_extractors import extract_datetime_features


class DateTimeRiskModel(BaseRiskModel):
    """
    DateTime Risk Model using Isolation Forest.
    Detects unusual login times, burst patterns, and timing anomalies.
    """
    
    def __init__(self, version: str = "v1.0.0"):
        super().__init__("datetime_risk_model", version)
        self.scaler = StandardScaler()
        self.feature_names = [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours',
            'is_night', 'time_since_last_login', 'login_velocity',
            'is_burst_pattern', 'hour_deviation', 'login_frequency'
        ]
    
    def extract_features(self, current_session: Dict, login_history: List[Dict]) -> np.ndarray:
        """Extract datetime-related features."""
        timestamp = current_session['timestamp']
        history_timestamps = [item['timestamp'] for item in login_history]
        
        # Get basic datetime features
        features = extract_datetime_features(timestamp, history_timestamps)
        
        # Add advanced features
        hour_deviation = self._calculate_hour_deviation(timestamp, history_timestamps)
        login_frequency = self._calculate_login_frequency(history_timestamps)
        
        # Create feature vector
        feature_vector = [
            features['hour'] / 23,  # Normalize to 0-1
            features['day_of_week'] / 6,  # Normalize to 0-1
            features['is_weekend'],
            features['is_business_hours'],
            features['is_night'],
            min(features['time_since_last_login'] / 168, 1),  # Normalize to 0-1 (cap at 1 week)
            min(features['login_velocity'] / 10, 1),  # Normalize to 0-1 (cap at 10/hour)
            float(features['is_burst_pattern']),
            hour_deviation,
            login_frequency
        ]
        
        return np.array(feature_vector)
    
    def _calculate_hour_deviation(self, timestamp: int, history_timestamps: List[int]) -> float:
        """Calculate deviation from user's typical login hours."""
        if not history_timestamps:
            return 0.5  # Neutral value for new users
        
        # Get hours from historical logins
        historical_hours = []
        for ts in history_timestamps:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            historical_hours.append(dt.hour)
        
        # Calculate mean hour (circular mean for hours)
        if historical_hours:
            # Convert hours to angles
            angles = [h * (2 * np.pi / 24) for h in historical_hours]
            mean_sin = np.mean([np.sin(a) for a in angles])
            mean_cos = np.mean([np.cos(a) for a in angles])
            mean_angle = np.arctan2(mean_sin, mean_cos)
            mean_hour = mean_angle * (24 / (2 * np.pi))
            if mean_hour < 0:
                mean_hour += 24
            
            # Calculate deviation
            current_hour = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).hour
            deviation = min(abs(current_hour - mean_hour), 24 - abs(current_hour - mean_hour))
            return deviation / 12  # Normalize to 0-1
        
        return 0.5
    
    def _calculate_login_frequency(self, history_timestamps: List[int]) -> float:
        """Calculate average login frequency."""
        if len(history_timestamps) < 2:
            return 0.0
        
        # Sort timestamps
        sorted_ts = sorted(history_timestamps)
        
        # Calculate average time between logins (in days)
        intervals = []
        for i in range(1, len(sorted_ts)):
            interval_ms = sorted_ts[i] - sorted_ts[i-1]
            interval_days = interval_ms / (1000 * 60 * 60 * 24)
            intervals.append(interval_days)
        
        if intervals:
            avg_interval = np.mean(intervals)
            # Convert to frequency (logins per week)
            frequency = 7 / max(avg_interval, 0.1)
            return min(frequency / 20, 1)  # Normalize (cap at 20 logins/week)
        
        return 0.0
    
    def train(self, training_data: Dict) -> None:
        """
        Train the Isolation Forest model.
        
        Args:
            training_data: Dictionary with 'normal' and 'anomalous' login patterns
        """
        # Extract features for normal patterns
        normal_features = []
        for pattern in training_data['normal']:
            features = self.extract_features(
                {'timestamp': pattern['timestamp']},
                pattern.get('history', [])
            )
            normal_features.append(features)
        
        # Add some anomalous patterns for contamination
        anomalous_features = []
        for pattern in training_data['anomalous']:
            features = self.extract_features(
                {'timestamp': pattern['timestamp']},
                pattern.get('history', [])
            )
            anomalous_features.append(features)
        
        # Combine data
        X_train = np.vstack([normal_features, anomalous_features[:len(anomalous_features)//10]])
        
        # Fit scaler
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Expected 10% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled)
        self.is_loaded = True
        
        print(f"DateTime Risk Model trained with {len(X_train)} samples")
    
    def predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Override predict to include scaling and rule-based adjustments."""
        if not self.is_loaded:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Extract and scale features
        features = self.extract_features(current_session, login_history)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get anomaly score
        anomaly_score = self.model.score_samples(features_scaled)[0]
        
        # Calculate base risk from Isolation Forest
        base_risk = self._normalize_score(-anomaly_score, method='isolation_forest')
        
        # Apply rules-based adjustments
        risk_adjustments = self._apply_risk_rules(current_session, login_history)
        
        # Combine base risk with adjustments
        final_risk = base_risk + risk_adjustments
        
        return max(0, min(100, final_risk))
    
    def _apply_risk_rules(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Apply additional risk rules based on datetime patterns."""
        adjustment = 0
        timestamp = current_session['timestamp']
        dt = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
        
        # Extract features for rule evaluation
        history_timestamps = [item['timestamp'] for item in login_history]
        features = extract_datetime_features(timestamp, history_timestamps)
        
        # High risk for unusual hours (2-5 AM)
        if 2 <= dt.hour <= 5:
            adjustment += 20
        
        # Burst pattern detection
        if features['is_burst_pattern']:
            adjustment += 25
        
        # Very high velocity (potential brute force)
        if features['login_velocity'] > 20:  # More than 20 attempts per hour
            adjustment += 30
        
        # First login ever at unusual time
        if not history_timestamps and features['is_night']:
            adjustment += 15
        
        # Long dormancy followed by activity
        if features['time_since_last_login'] > 720:  # More than 30 days
            adjustment += 10
        
        return adjustment
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save model and scaler."""
        import os
        import joblib
        
        # First save the base model
        super().save_model(path)
        
        # Also save the scaler
        model_path = path or self.model_path
        scaler_path = model_path.replace('.pkl', '_scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model and scaler."""
        import os
        import joblib
        
        # First load the base model
        if not super().load_model(path):
            return False
        
        # Also load the scaler
        model_path = path or self.model_path
        scaler_path = model_path.replace('.pkl', '_scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        else:
            print(f"Warning: Scaler file not found at {scaler_path}")
            self.scaler = StandardScaler()
        
        return True