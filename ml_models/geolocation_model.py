"""
Geolocation Risk Model using DBSCAN clustering + physics validation
Detects: Impossible travel, location anomalies, country hopping
"""
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List, Tuple
from math import radians, sin, cos, sqrt, atan2
import logging
from datetime import datetime

from ml_models.base_model import BaseRiskModel

logger = logging.getLogger(__name__)


class GeolocationRiskModel(BaseRiskModel):
    """DBSCAN model for geolocation anomaly detection with physics validation"""
    
    def __init__(self, model_path: str = None):
        super().__init__("Geolocation Risk Model", model_path)
        self.scaler = StandardScaler()
        self.max_travel_speed_kmh = 900.0  # Max feasible travel speed
        self.earth_radius_km = 6371.0
        
        # High-risk countries (simplified list)
        self.high_risk_countries = {
            'North Korea', 'Iran', 'Syria', 'Cuba', 'Crimea'
        }
        
    def haversine_distance(self, lat1: float, lon1: float, 
                          lat2: float, lon2: float) -> float:
        """Calculate distance between two points on Earth in kilometers"""
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return self.earth_radius_km * c
    
    def calculate_travel_speed(self, loc1: Dict, loc2: Dict, 
                             time1: int, time2: int) -> float:
        """Calculate travel speed between two locations in km/h"""
        distance = self.haversine_distance(
            loc1['latitude'], loc1['longitude'],
            loc2['latitude'], loc2['longitude']
        )
        
        time_diff_hours = abs(time2 - time1) / 3600000.0  # ms to hours
        
        if time_diff_hours == 0:
            return float('inf')
        
        return distance / time_diff_hours
    
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract geolocation-based features"""
        current_location = data.get('location', {})
        timestamp = data.get('timestamp', 0)
        login_history = data.get('login_history', [])
        
        features = []
        
        try:
            # Current location features
            lat = current_location.get('latitude', 0)
            lon = current_location.get('longitude', 0)
            features.append(lat / 90.0)  # Normalize
            features.append(lon / 180.0)  # Normalize
            
            # Country risk
            country = current_location.get('country', '')
            features.append(1 if country in self.high_risk_countries else 0)
            
            if login_history:
                # Distance from last location
                last_login = max(login_history, key=lambda x: x['timestamp'])
                last_loc = last_login.get('location', {})
                
                if last_loc:
                    distance = self.haversine_distance(
                        lat, lon,
                        last_loc.get('latitude', lat),
                        last_loc.get('longitude', lon)
                    )
                    features.append(min(distance / 10000.0, 1.0))  # Normalize
                    
                    # Travel speed
                    speed = self.calculate_travel_speed(
                        current_location, last_loc,
                        timestamp, last_login['timestamp']
                    )
                    features.append(min(speed / 1000.0, 2.0))  # Normalize
                    
                    # Impossible travel flag
                    features.append(1 if speed > self.max_travel_speed_kmh else 0)
                else:
                    features.extend([0, 0, 0])
                
                # Location diversity
                unique_countries = set(item.get('location', {}).get('country', '') 
                                     for item in login_history)
                features.append(len(unique_countries) / 10.0)  # Normalize
                
                # Number of location changes in last 24h
                recent_locations = []
                for item in login_history:
                    if timestamp - item['timestamp'] < 86400000:  # 24h
                        loc = item.get('location', {})
                        if loc:
                            recent_locations.append((loc.get('latitude'), loc.get('longitude')))
                
                unique_recent = len(set(recent_locations))
                features.append(unique_recent / 5.0)  # Normalize
                
                # Average distance between consecutive logins
                distances = []
                sorted_history = sorted(login_history, key=lambda x: x['timestamp'])
                for i in range(1, min(len(sorted_history), 10)):
                    loc1 = sorted_history[i-1].get('location', {})
                    loc2 = sorted_history[i].get('location', {})
                    if loc1 and loc2:
                        dist = self.haversine_distance(
                            loc1.get('latitude', 0), loc1.get('longitude', 0),
                            loc2.get('latitude', 0), loc2.get('longitude', 0)
                        )
                        distances.append(dist)
                
                avg_distance = np.mean(distances) if distances else 0
                features.append(min(avg_distance / 5000.0, 1.0))  # Normalize
                
            else:
                features.extend([0, 0, 0, 0, 0, 0])
                
        except Exception as e:
            logger.error(f"Error extracting geolocation features: {e}")
            features = [0] * 9
            
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """Train DBSCAN on normal location patterns"""
        logger.info("Training Geolocation Risk Model...")
        
        # Extract location coordinates for clustering
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features[0])
        
        X = np.array(X)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train DBSCAN
        self.model = DBSCAN(
            eps=0.3,
            min_samples=5,
            metric='euclidean'
        )
        self.model.fit(X_scaled)
        
        # Store core samples for distance calculation
        self.core_samples = X_scaled[self.model.core_sample_indices_]
        
        logger.info(f"Geolocation model trained on {len(X)} samples")
    
    def predict_risk(self, current_session: Dict[str, Any], 
                    login_history: List[Dict[str, Any]] = None) -> int:
        """Predict risk score for current geolocation"""
        if not self.is_loaded and self.model is None:
            logger.warning("Model not loaded, returning default score")
            return 50
        
        try:
            # Get location from IP if not provided
            # In production, this would use a GeoIP service
            location = {
                'latitude': 40.7128,  # Default NYC
                'longitude': -74.0060,
                'country': 'United States',
                'city': 'New York'
            }
            
            # Prepare data
            data = {
                'location': location,
                'timestamp': current_session.get('timestamp', 0),
                'login_history': login_history or []
            }
            
            # Extract features
            features = self.extract_features(data)
            features_scaled = self.scaler.transform(features)
            
            # Calculate minimum distance to core samples
            if hasattr(self, 'core_samples') and len(self.core_samples) > 0:
                distances = np.min([np.linalg.norm(features_scaled - core) 
                                  for core in self.core_samples])
                
                # Convert distance to risk score
                if distances < 0.3:  # Within normal cluster
                    base_risk = int(30 * (distances / 0.3))
                else:
                    base_risk = 30 + int(70 * (1 - np.exp(-distances)))
            else:
                base_risk = 50
            
            base_risk = max(0, min(100, base_risk))
            
            # Physics-based validation
            if login_history:
                # Check for impossible travel
                last_login = max(login_history, key=lambda x: x['timestamp'])
                last_loc = last_login.get('location', {})
                
                if last_loc:
                    speed = self.calculate_travel_speed(
                        location, last_loc,
                        current_session['timestamp'], 
                        last_login['timestamp']
                    )
                    
                    if speed > self.max_travel_speed_kmh:
                        # Impossible travel detected
                        base_risk = max(base_risk, 85)
                        
                        # More impossible = higher risk
                        if speed > 2000:  # Way beyond possible
                            base_risk = 95
                    
                    # Suspicious but possible travel
                    elif speed > 500:  # Faster than typical commercial flight
                        base_risk = min(100, base_risk + 20)
                
                # Country hopping
                recent_countries = []
                current_time = current_session['timestamp']
                for item in login_history[-10:]:
                    if current_time - item['timestamp'] < 86400000:  # 24h
                        country = item.get('location', {}).get('country')
                        if country:
                            recent_countries.append(country)
                
                unique_countries = len(set(recent_countries))
                if unique_countries > 3:  # Many countries in 24h
                    base_risk = min(100, base_risk + 15)
            
            # High-risk country check
            if location.get('country') in self.high_risk_countries:
                base_risk = max(base_risk, 70)
            
            return base_risk
            
        except Exception as e:
            logger.error(f"Error in geolocation risk prediction: {e}")
            return 50