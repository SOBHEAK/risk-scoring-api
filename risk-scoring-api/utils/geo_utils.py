# utils/geo_utils.py
import math
from typing import Tuple, Dict, Optional
from datetime import datetime, timezone


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points on Earth.
    
    Args:
        lat1, lon1: Latitude and longitude of first point
        lat2, lon2: Latitude and longitude of second point
        
    Returns:
        Distance in kilometers
    """
    # Radius of Earth in kilometers
    R = 6371.0
    
    # Convert to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    return R * c


def calculate_travel_speed(distance_km: float, time_diff_hours: float) -> float:
    """
    Calculate travel speed between two locations.
    
    Args:
        distance_km: Distance in kilometers
        time_diff_hours: Time difference in hours
        
    Returns:
        Speed in km/h
    """
    if time_diff_hours <= 0:
        return float('inf')
    
    return distance_km / time_diff_hours


def is_impossible_travel(lat1: float, lon1: float, timestamp1: int,
                        lat2: float, lon2: float, timestamp2: int,
                        max_speed_kmh: float = 900) -> bool:
    """
    Check if travel between two locations is physically impossible.
    
    Args:
        lat1, lon1: First location
        timestamp1: First timestamp (milliseconds)
        lat2, lon2: Second location
        timestamp2: Second timestamp (milliseconds)
        max_speed_kmh: Maximum possible travel speed (default 900 km/h for air travel)
        
    Returns:
        True if travel is impossible, False otherwise
    """
    # Calculate distance
    distance = haversine_distance(lat1, lon1, lat2, lon2)
    
    # Calculate time difference in hours
    time_diff_ms = abs(timestamp2 - timestamp1)
    time_diff_hours = time_diff_ms / (1000 * 60 * 60)
    
    # Avoid division by zero
    if time_diff_hours < 0.001:  # Less than 3.6 seconds
        # If locations are different but time is almost same, it's impossible
        return distance > 0.1  # More than 100 meters
    
    # Calculate required speed
    required_speed = calculate_travel_speed(distance, time_diff_hours)
    
    return required_speed > max_speed_kmh


def get_country_risk_score(country: str) -> int:
    """
    Get risk score based on country.
    
    Args:
        country: Country name
        
    Returns:
        Risk score (0-100)
    """
    # High-risk countries for cybercrime (simplified list)
    high_risk_countries = {
        'North Korea': 95,
        'Iran': 85,
        'China': 75,
        'Russia': 75,
        'Nigeria': 70,
        'Romania': 65,
        'Brazil': 60,
        'India': 55,
        'Vietnam': 55,
        'Indonesia': 50,
    }
    
    # Low-risk countries
    low_risk_countries = {
        'United States': 10,
        'Canada': 10,
        'United Kingdom': 10,
        'Germany': 10,
        'France': 10,
        'Australia': 10,
        'Japan': 10,
        'South Korea': 15,
        'Singapore': 15,
        'Netherlands': 15,
    }
    
    # Check high-risk countries first
    if country in high_risk_countries:
        return high_risk_countries[country]
    
    # Check low-risk countries
    if country in low_risk_countries:
        return low_risk_countries[country]
    
    # Default moderate risk for unknown countries
    return 30


def analyze_location_pattern(current_location: Dict, history_locations: list) -> Dict[str, float]:
    """
    Analyze location patterns for anomalies.
    
    Args:
        current_location: Current location dict with country, city, lat, lon
        history_locations: List of historical location dicts
        
    Returns:
        Dictionary of location risk features
    """
    features = {
        'is_new_country': 1.0,
        'is_new_city': 1.0,
        'country_switches': 0,
        'avg_distance_from_history': 0.0,
        'max_distance_from_history': 0.0,
        'location_variance': 0.0,
    }
    
    if not history_locations:
        return features
    
    # Check if country/city are new
    historical_countries = [loc['country'] for loc in history_locations]
    historical_cities = [loc['city'] for loc in history_locations]
    
    features['is_new_country'] = float(current_location['country'] not in historical_countries)
    features['is_new_city'] = float(current_location['city'] not in historical_cities)
    
    # Count country switches
    for i in range(1, len(history_locations)):
        if history_locations[i]['country'] != history_locations[i-1]['country']:
            features['country_switches'] += 1
    
    # Calculate distances from historical locations
    distances = []
    for hist_loc in history_locations:
        dist = haversine_distance(
            current_location['latitude'], current_location['longitude'],
            hist_loc['latitude'], hist_loc['longitude']
        )
        distances.append(dist)
    
    if distances:
        features['avg_distance_from_history'] = sum(distances) / len(distances)
        features['max_distance_from_history'] = max(distances)
        
        # Calculate variance
        if len(distances) > 1:
            mean = features['avg_distance_from_history']
            variance = sum((d - mean) ** 2 for d in distances) / len(distances)
            features['location_variance'] = math.sqrt(variance)
    
    return features


def get_timezone_from_location(latitude: float, longitude: float) -> Optional[str]:
    """
    Estimate timezone from coordinates (simplified version).
    
    Args:
        latitude: Latitude
        longitude: Longitude
        
    Returns:
        Estimated timezone offset string
    """
    # Simplified timezone calculation based on longitude
    # Each 15 degrees of longitude = 1 hour offset
    offset_hours = round(longitude / 15)
    
    if offset_hours >= 0:
        return f"+{offset_hours:02d}:00"
    else:
        return f"{offset_hours:03d}:00"