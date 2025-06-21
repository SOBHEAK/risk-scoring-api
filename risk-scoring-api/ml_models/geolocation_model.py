# ml_models/geolocation_model.py
import os
import joblib
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional, Tuple
from ml_models.base_model import BaseRiskModel
from utils.geo_utils import (
    haversine_distance, is_impossible_travel, 
    get_country_risk_score, analyze_location_pattern
)


class GeolocationRiskModel(BaseRiskModel):
    """
    Geolocation Risk Model using DBSCAN clustering.
    Detects impossible travel, location anomalies, and suspicious geographic patterns.
    """
    
    def __init__(self, version: str = "v1.0.0"):
        super().__init__("geolocation_risk_model", version)
        self.scaler = StandardScaler()
        self.location_clusters = {}
        self.feature_names = [
            'is_new_country', 'is_new_city', 'country_risk',
            'avg_distance_from_history', 'max_distance_from_history',
            'impossible_travel_flag', 'location_variance', 'cluster_distance'
        ]
    
    def extract_features(self, current_session: Dict, login_history: List[Dict]) -> np.ndarray:
        """Extract geolocation features."""
        # Get current location from session or history
        current_location = self._get_current_location(current_session, login_history)
        
        if not current_location:
            # Return neutral features if location unavailable
            return np.zeros(len(self.feature_names))
        
        # Get location pattern features
        history_locations = [item['location'] for item in login_history if 'location' in item]
        location_features = analyze_location_pattern(current_location, history_locations)
        
        # Check for impossible travel
        impossible_travel = self._check_impossible_travel(
            current_session['timestamp'],
            current_location,
            login_history
        )
        
        # Get country risk score
        country_risk = get_country_risk_score(current_location['country']) / 100
        
        # Calculate cluster distance
        cluster_distance = self._calculate_cluster_distance(current_location)
        
        # Create feature vector
        feature_vector = [
            location_features['is_new_country'],
            location_features['is_new_city'],
            country_risk,
            min(location_features['avg_distance_from_history'] / 5000, 1),  # Normalize
            min(location_features['max_distance_from_history'] / 10000, 1),  # Normalize
            float(impossible_travel),
            min(location_features['location_variance'] / 1000, 1),  # Normalize
            cluster_distance
        ]
        
        return np.array(feature_vector)
    
    def _get_current_location(self, current_session: Dict, 
                            login_history: List[Dict]) -> Optional[Dict]:
        """Extract or estimate current location."""
        # In real implementation, would use IP geolocation service
        # For now, simulate with the most recent location if available
        if login_history and 'location' in login_history[-1]:
            # Use last known location as approximation
            last_location = login_history[-1]['location']
            return {
                'country': last_location['country'],
                'city': last_location['city'],
                'latitude': last_location['latitude'],
                'longitude': last_location['longitude']
            }
        
        # Default location (could be enriched with IP geolocation)
        return {
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        }
    
    def _check_impossible_travel(self, current_timestamp: int,
                                current_location: Dict,
                                login_history: List[Dict]) -> bool:
        """Check for physically impossible travel."""
        if not login_history:
            return False
        
        # Find the most recent login with location
        for item in reversed(login_history):
            if 'location' in item:
                prev_location = item['location']
                prev_timestamp = item['timestamp']
                
                return is_impossible_travel(
                    prev_location['latitude'], prev_location['longitude'], prev_timestamp,
                    current_location['latitude'], current_location['longitude'], current_timestamp
                )
        
        return False
    
    def _calculate_cluster_distance(self, location: Dict) -> float:
        """Calculate distance to nearest known cluster."""
        if not self.location_clusters:
            return 0.5  # Neutral value
        
        min_distance = float('inf')
        location_point = np.array([location['latitude'], location['longitude']])
        
        for cluster_id, cluster_center in self.location_clusters.items():
            distance = np.linalg.norm(location_point - cluster_center)
            min_distance = min(min_distance, distance)
        
        # Normalize distance (approximate degrees to risk score)
        return min(min_distance / 50, 1)  # 50 degrees as max
    
    def train(self, training_data: Dict) -> None:
        """
        Train the DBSCAN clustering model.
        
        Args:
            training_data: Dictionary with location data
        """
        # Extract location coordinates
        coordinates = []
        for location_data in training_data['locations']:
            coords = [location_data['latitude'], location_data['longitude']]
            coordinates.append(coords)
        
        X_train = np.array(coordinates)
        
        # Fit scaler on coordinates
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        
        # Train DBSCAN
        self.model = DBSCAN(
            eps=0.3,  # Maximum distance between samples
            min_samples=5,  # Minimum cluster size
            metric='euclidean',
            n_jobs=-1
        )
        
        cluster_labels = self.model.fit_predict(X_train_scaled)
        
        # Calculate cluster centers
        self.location_clusters = {}
        for cluster_id in set(cluster_labels):
            if cluster_id != -1:  # -1 is noise
                cluster_points = X_train[cluster_labels == cluster_id]
                cluster_center = np.mean(cluster_points, axis=0)
                self.location_clusters[cluster_id] = cluster_center
        
        self.is_loaded = True
        print(f"Geolocation Risk Model trained with {len(X_train)} samples, "
              f"found {len(self.location_clusters)} clusters")
    
    def predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Override predict to include physics-based validation."""
        if not self.is_loaded:
            # Use rules-based approach if model not loaded
            return self._rules_based_predict(current_session, login_history)
        
        # Extract features
        features = self.extract_features(current_session, login_history)
        
        # Calculate base risk from features
        base_risk = self._calculate_feature_risk(features)
        
        # Apply physics-based rules
        risk_adjustments = self._apply_physics_rules(current_session, login_history)
        
        # Combine risks
        final_risk = base_risk + risk_adjustments
        
        return max(0, min(100, final_risk))
    
    def _calculate_feature_risk(self, features: np.ndarray) -> int:
        """Calculate risk score from features."""
        # Weight different features
        weights = np.array([
            0.15,  # is_new_country
            0.10,  # is_new_city
            0.20,  # country_risk
            0.10,  # avg_distance_from_history
            0.10,  # max_distance_from_history
            0.25,  # impossible_travel_flag
            0.05,  # location_variance
            0.05   # cluster_distance
        ])
        
        # Calculate weighted risk
        risk_score = np.dot(features, weights) * 100
        
        return int(risk_score)
    
    def _apply_physics_rules(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Apply physics-based validation rules."""
        adjustment = 0
        
        current_location = self._get_current_location(current_session, login_history)
        if not current_location:
            return adjustment
        
        # Check for impossible travel
        if self._check_impossible_travel(current_session['timestamp'], 
                                       current_location, login_history):
            adjustment += 40  # Very high risk for impossible travel
        
        # Check for suspicious country patterns
        if login_history:
            countries = [item['location']['country'] 
                        for item in login_history[-5:] 
                        if 'location' in item]
            countries.append(current_location['country'])
            
            # Too many different countries in recent logins
            if len(set(countries)) > 3:
                adjustment += 20
        
        # High-risk country
        country_risk = get_country_risk_score(current_location['country'])
        if country_risk > 70:
            adjustment += 15
        
        return adjustment
    
    def _rules_based_predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Fallback prediction using only rules when model not loaded."""
        risk = 0
        
        current_location = self._get_current_location(current_session, login_history)
        if not current_location:
            return 50  # Medium risk for unknown location
        
        # Check impossible travel
        if self._check_impossible_travel(current_session['timestamp'], 
                                       current_location, login_history):
            risk += 80
        
        # Check country risk
        risk += get_country_risk_score(current_location['country']) * 0.7
        
        # Check for new location
        if login_history:
            history_countries = [item['location']['country'] 
                               for item in login_history 
                               if 'location' in item]
            if current_location['country'] not in history_countries:
                risk += 20
        
        return max(0, min(100, int(risk)))
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save model, scaler, and clusters."""
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'location_clusters': self.location_clusters,
            'version': self.version,
            'model_name': self.model_name,
        }
        
        joblib.dump(model_data, save_path)
        print(f"Geolocation model saved to {save_path}")
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model, scaler, and clusters."""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            print(f"Model file not found: {load_path}")
            return False
        
        try:
            model_data = joblib.load(load_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.location_clusters = model_data.get('location_clusters', {})
            self.version = model_data.get('version', 'unknown')
            
            self.is_loaded = True
            print(f"Geolocation model loaded successfully")
            return True
            
        except Exception as e:
            print(f"Error loading Geolocation model: {e}")
            return False