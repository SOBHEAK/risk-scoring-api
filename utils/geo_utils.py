"""
Geolocation utilities
"""
from math import radians, sin, cos, sqrt, atan2
from typing import Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class GeoLocationAnalyzer:
    """Analyze geolocation data for anomalies"""
    
    def __init__(self):
        self.earth_radius_km = 6371.0
        self.max_commercial_flight_speed_kmh = 900.0
        self.max_ground_speed_kmh = 300.0  # High-speed rail
        
        # Major cities with coordinates (for testing)
        self.major_cities = {
            'New York': (40.7128, -74.0060),
            'London': (51.5074, -0.1278),
            'Tokyo': (35.6762, 139.6503),
            'Sydney': (-33.8688, 151.2093),
            'Dubai': (25.2048, 55.2708),
            'Singapore': (1.3521, 103.8198),
            'San Francisco': (37.7749, -122.4194),
            'Paris': (48.8566, 2.3522),
            'Mumbai': (19.0760, 72.8777),
            'Beijing': (39.9042, 116.4074),
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
    
    def calculate_travel_speed(self, lat1: float, lon1: float,
                             lat2: float, lon2: float,
                             time_diff_ms: int) -> float:
        """Calculate required travel speed in km/h"""
        if time_diff_ms <= 0:
            return float('inf')
        
        distance_km = self.haversine_distance(lat1, lon1, lat2, lon2)
        time_diff_hours = time_diff_ms / 3600000.0  # Convert ms to hours
        
        return distance_km / time_diff_hours
    
    def is_impossible_travel(self, lat1: float, lon1: float,
                           lat2: float, lon2: float,
                           time_diff_ms: int) -> bool:
        """Check if travel between two points is physically impossible"""
        speed = self.calculate_travel_speed(lat1, lon1, lat2, lon2, time_diff_ms)
        return speed > self.max_commercial_flight_speed_kmh
    
    def get_location_risk_factors(self, country: str, city: str) -> Dict[str, any]:
        """Get risk factors for a location"""
        risk_factors = {
            'is_high_risk_country': False,
            'is_sanctioned': False,
            'risk_score': 0
        }
        
        # High-risk countries (simplified list)
        high_risk_countries = {
            'North Korea', 'Iran', 'Syria', 'Cuba', 'Sudan',
            'Russia', 'Belarus', 'Myanmar', 'Venezuela'
        }
        
        # Sanctioned regions
        sanctioned_regions = {
            'Crimea', 'Donetsk', 'Luhansk'
        }
        
        if country in high_risk_countries:
            risk_factors['is_high_risk_country'] = True
            risk_factors['risk_score'] = 70
        
        if city in sanctioned_regions:
            risk_factors['is_sanctioned'] = True
            risk_factors['risk_score'] = 90
        
        return risk_factors
    
    def analyze_location_pattern(self, locations: list) -> Dict[str, any]:
        """Analyze patterns in location history"""
        if not locations:
            return {
                'unique_countries': 0,
                'unique_cities': 0,
                'max_distance': 0,
                'total_distance': 0,
                'suspicious_pattern': False
            }
        
        countries = set()
        cities = set()
        max_distance = 0
        total_distance = 0
        
        for i, loc in enumerate(locations):
            if 'country' in loc:
                countries.add(loc['country'])
            if 'city' in loc:
                cities.add(loc['city'])
            
            # Calculate distances between consecutive locations
            if i > 0 and 'latitude' in loc and 'latitude' in locations[i-1]:
                dist = self.haversine_distance(
                    locations[i-1]['latitude'], locations[i-1]['longitude'],
                    loc['latitude'], loc['longitude']
                )
                total_distance += dist
                max_distance = max(max_distance, dist)
        
        # Detect suspicious patterns
        suspicious = False
        
        # Too many countries in short time
        if len(countries) > 5:
            suspicious = True
        
        # Ping-ponging between distant locations
        if len(locations) > 2:
            distances = []
            for i in range(1, len(locations)):
                if 'latitude' in locations[i] and 'latitude' in locations[i-1]:
                    dist = self.haversine_distance(
                        locations[i-1]['latitude'], locations[i-1]['longitude'],
                        locations[i]['latitude'], locations[i]['longitude']
                    )
                    distances.append(dist)
            
            # Check for alternating pattern (A->B->A->B)
            if len(distances) > 3:
                for i in range(2, len(distances)):
                    if (distances[i] > 1000 and distances[i-2] > 1000 and
                        distances[i-1] < 100):  # Long-short-long pattern
                        suspicious = True
                        break
        
        return {
            'unique_countries': len(countries),
            'unique_cities': len(cities),
            'max_distance': max_distance,
            'total_distance': total_distance,
            'suspicious_pattern': suspicious
        }
    
    def get_city_from_coordinates(self, lat: float, lon: float) -> Optional[str]:
        """Get nearest major city from coordinates (simplified)"""
        min_distance = float('inf')
        nearest_city = None
        
        for city, (city_lat, city_lon) in self.major_cities.items():
            distance = self.haversine_distance(lat, lon, city_lat, city_lon)
            if distance < min_distance:
                min_distance = distance
                nearest_city = city
        
        # If within 50km of a major city, return it
        if min_distance < 50:
            return nearest_city
        
        return None
    
    def validate_coordinates(self, lat: float, lon: float) -> bool:
        """Validate if coordinates are valid"""
        return -90 <= lat <= 90 and -180 <= lon <= 180