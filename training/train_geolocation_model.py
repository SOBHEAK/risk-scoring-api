"""
Train Geolocation Risk Model using synthetic data
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import random
from datetime import datetime, timedelta
from ml_models.geolocation_model import GeolocationRiskModel
from config.settings import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Major cities with coordinates
CITIES = {
    'New York': {'lat': 40.7128, 'lon': -74.0060, 'country': 'United States'},
    'Los Angeles': {'lat': 34.0522, 'lon': -118.2437, 'country': 'United States'},
    'Chicago': {'lat': 41.8781, 'lon': -87.6298, 'country': 'United States'},
    'Houston': {'lat': 29.7604, 'lon': -95.3698, 'country': 'United States'},
    'London': {'lat': 51.5074, 'lon': -0.1278, 'country': 'United Kingdom'},
    'Paris': {'lat': 48.8566, 'lon': 2.3522, 'country': 'France'},
    'Berlin': {'lat': 52.5200, 'lon': 13.4050, 'country': 'Germany'},
    'Tokyo': {'lat': 35.6762, 'lon': 139.6503, 'country': 'Japan'},
    'Sydney': {'lat': -33.8688, 'lon': 151.2093, 'country': 'Australia'},
    'Mumbai': {'lat': 19.0760, 'lon': 72.8777, 'country': 'India'},
    'Singapore': {'lat': 1.3521, 'lon': 103.8198, 'country': 'Singapore'},
    'Dubai': {'lat': 25.2048, 'lon': 55.2708, 'country': 'United Arab Emirates'},
    'Beijing': {'lat': 39.9042, 'lon': 116.4074, 'country': 'China'},
    'Moscow': {'lat': 55.7558, 'lon': 37.6173, 'country': 'Russia'},
    'São Paulo': {'lat': -23.5505, 'lon': -46.6333, 'country': 'Brazil'},
    'Toronto': {'lat': 43.6532, 'lon': -79.3832, 'country': 'Canada'},
    'Mexico City': {'lat': 19.4326, 'lon': -99.1332, 'country': 'Mexico'},
    'Bangkok': {'lat': 13.7563, 'lon': 100.5018, 'country': 'Thailand'},
    'Seoul': {'lat': 37.5665, 'lon': 126.9780, 'country': 'South Korea'},
    'Cairo': {'lat': 30.0444, 'lon': 31.2357, 'country': 'Egypt'},
}


def generate_user_location_pattern():
    """Generate a realistic user location pattern"""
    patterns = [
        {
            'type': 'local_user',
            'home_city': random.choice(list(CITIES.keys())),
            'travel_frequency': 'never',
            'max_distance': 50  # km
        },
        {
            'type': 'regional_traveler',
            'home_city': random.choice(list(CITIES.keys())),
            'travel_frequency': 'monthly',
            'max_distance': 500  # km
        },
        {
            'type': 'business_traveler',
            'home_city': random.choice(list(CITIES.keys())),
            'travel_frequency': 'weekly',
            'max_distance': 5000  # km
        },
        {
            'type': 'international_traveler',
            'home_city': random.choice(list(CITIES.keys())),
            'travel_frequency': 'frequent',
            'max_distance': 20000  # km
        }
    ]
    
    return random.choice(patterns)


def add_location_noise(lat, lon, max_km=50):
    """Add random noise to coordinates within max_km radius"""
    # Approximate degrees per km
    km_per_degree_lat = 111.0
    km_per_degree_lon = 111.0 * np.cos(np.radians(lat))
    
    # Random distance and angle
    distance_km = random.uniform(0, max_km)
    angle = random.uniform(0, 2 * np.pi)
    
    # Calculate offset
    lat_offset = (distance_km * np.sin(angle)) / km_per_degree_lat
    lon_offset = (distance_km * np.cos(angle)) / km_per_degree_lon
    
    return lat + lat_offset, lon + lon_offset


def generate_legitimate_location_history(pattern, num_days=30):
    """Generate location history based on user pattern"""
    history = []
    current_time = datetime.now()
    home_city_data = CITIES[pattern['home_city']]
    
    for day in range(num_days):
        date = current_time - timedelta(days=day)
        num_logins = random.randint(1, 3)
        
        for _ in range(num_logins):
            # Determine location based on pattern
            if pattern['travel_frequency'] == 'never':
                # Always home
                lat, lon = add_location_noise(
                    home_city_data['lat'], 
                    home_city_data['lon'], 
                    20
                )
                city = pattern['home_city']
                country = home_city_data['country']
                
            elif random.random() < 0.8:  # 80% at home
                lat, lon = add_location_noise(
                    home_city_data['lat'], 
                    home_city_data['lon'], 
                    20
                )
                city = pattern['home_city']
                country = home_city_data['country']
                
            else:  # Traveling
                # Pick a city within travel range
                possible_cities = []
                home_lat = home_city_data['lat']
                home_lon = home_city_data['lon']
                
                for city_name, city_data in CITIES.items():
                    if city_name == pattern['home_city']:
                        continue
                        
                    # Calculate distance
                    distance = np.sqrt(
                        (city_data['lat'] - home_lat)**2 + 
                        (city_data['lon'] - home_lon)**2
                    ) * 111  # Rough km conversion
                    
                    if distance <= pattern['max_distance']:
                        possible_cities.append(city_name)
                
                if possible_cities:
                    travel_city = random.choice(possible_cities)
                    travel_data = CITIES[travel_city]
                    lat, lon = add_location_noise(
                        travel_data['lat'], 
                        travel_data['lon'], 
                        20
                    )
                    city = travel_city
                    country = travel_data['country']
                else:
                    # Stay home if no cities in range
                    lat, lon = add_location_noise(
                        home_city_data['lat'], 
                        home_city_data['lon'], 
                        20
                    )
                    city = pattern['home_city']
                    country = home_city_data['country']
            
            timestamp = int((date - timedelta(hours=random.randint(0, 23))).timestamp() * 1000)
            
            history.append({
                'timestamp': timestamp,
                'location': {
                    'latitude': lat,
                    'longitude': lon,
                    'city': city,
                    'country': country
                },
                'loginStatus': 'success' if random.random() > 0.05 else 'failure'
            })
    
    return sorted(history, key=lambda x: x['timestamp'], reverse=True)


def generate_training_data(num_samples=10000):
    """Generate synthetic training data for legitimate users"""
    training_data = []
    
    for i in range(num_samples):
        # Generate user pattern
        pattern = generate_user_location_pattern()
        
        # Generate location history
        login_history = generate_legitimate_location_history(pattern)
        
        # Current location (usually home or recent travel destination)
        if login_history and random.random() < 0.9:  # 90% chance at last location
            current_location = login_history[0]['location'].copy()
            # Add small noise
            current_location['latitude'], current_location['longitude'] = add_location_noise(
                current_location['latitude'],
                current_location['longitude'],
                10
            )
        else:
            # At home
            home_data = CITIES[pattern['home_city']]
            lat, lon = add_location_noise(home_data['lat'], home_data['lon'], 20)
            current_location = {
                'latitude': lat,
                'longitude': lon,
                'city': pattern['home_city'],
                'country': home_data['country']
            }
        
        session_data = {
            'location': current_location,
            'timestamp': int(datetime.now().timestamp() * 1000),
            'login_history': login_history
        }
        
        training_data.append(session_data)
    
    return training_data


def generate_anomaly_data(num_samples=500):
    """Generate synthetic anomaly data"""
    anomaly_data = []
    
    anomaly_patterns = [
        'impossible_travel',
        'country_hopping',
        'high_risk_country',
        'ping_pong'
    ]
    
    for i in range(num_samples):
        pattern_type = random.choice(anomaly_patterns)
        current_time = datetime.now()
        login_history = []
        
        if pattern_type == 'impossible_travel':
            # Login from NYC then London in 1 hour
            nyc = CITIES['New York']
            london = CITIES['London']
            
            # Recent login from NYC
            login_history.append({
                'timestamp': int((current_time - timedelta(hours=1)).timestamp() * 1000),
                'location': {
                    'latitude': nyc['lat'],
                    'longitude': nyc['lon'],
                    'city': 'New York',
                    'country': nyc['country']
                },
                'loginStatus': 'success'
            })
            
            # Current login from London
            current_location = {
                'latitude': london['lat'],
                'longitude': london['lon'],
                'city': 'London',
                'country': london['country']
            }
            
        elif pattern_type == 'country_hopping':
            # Many different countries in short time
            cities = random.sample(list(CITIES.keys()), 8)
            
            for j, city_name in enumerate(cities):
                city_data = CITIES[city_name]
                login_history.append({
                    'timestamp': int((current_time - timedelta(hours=j*2)).timestamp() * 1000),
                    'location': {
                        'latitude': city_data['lat'],
                        'longitude': city_data['lon'],
                        'city': city_name,
                        'country': city_data['country']
                    },
                    'loginStatus': 'success'
                })
            
            # Current location
            current_city = random.choice(list(CITIES.keys()))
            current_data = CITIES[current_city]
            current_location = {
                'latitude': current_data['lat'],
                'longitude': current_data['lon'],
                'city': current_city,
                'country': current_data['country']
            }
            
        elif pattern_type == 'high_risk_country':
            # Login from sanctioned country
            current_location = {
                'latitude': 35.1258,
                'longitude': 33.4299,
                'city': 'Nicosia',
                'country': 'North Korea'  # Simulated high-risk
            }
            
            # Normal history
            pattern = generate_user_location_pattern()
            login_history = generate_legitimate_location_history(pattern, 10)
            
        elif pattern_type == 'ping_pong':
            # Alternating between distant locations
            nyc = CITIES['New York']
            tokyo = CITIES['Tokyo']
            
            for j in range(10):
                if j % 2 == 0:
                    loc = nyc
                    city = 'New York'
                else:
                    loc = tokyo
                    city = 'Tokyo'
                
                login_history.append({
                    'timestamp': int((current_time - timedelta(days=j)).timestamp() * 1000),
                    'location': {
                        'latitude': loc['lat'],
                        'longitude': loc['lon'],
                        'city': city,
                        'country': loc['country']
                    },
                    'loginStatus': 'success'
                })
            
            current_location = {
                'latitude': nyc['lat'],
                'longitude': nyc['lon'],
                'city': 'New York',
                'country': nyc['country']
            }
        
        session_data = {
            'location': current_location,
            'timestamp': int(current_time.timestamp() * 1000),
            'login_history': sorted(login_history, key=lambda x: x['timestamp'], reverse=True)
        }
        
        anomaly_data.append(session_data)
    
    return anomaly_data


def main():
    """Train the Geolocation Risk Model"""
    logger.info("Generating training data...")
    
    # Generate legitimate data
    legitimate_data = generate_training_data(10000)
    logger.info(f"Generated {len(legitimate_data)} legitimate samples")
    
    # Initialize and train model
    model = GeolocationRiskModel(f"{settings.MODELS_PATH}/geolocation_model.pkl")
    
    logger.info("Training Geolocation Risk Model...")
    model.train(legitimate_data)
    
    # Save model
    os.makedirs(settings.MODELS_PATH, exist_ok=True)
    model.save_model()
    logger.info(f"Model saved to {settings.MODELS_PATH}/geolocation_model.pkl")
    
    # Test on anomalies
    logger.info("Testing on anomaly data...")
    anomaly_data = generate_anomaly_data(100)
    
    legitimate_scores = []
    anomaly_scores = []
    
    # Test legitimate samples
    for data in legitimate_data[:100]:
        score = model.predict_risk(
            {'timestamp': data['timestamp']},
            data['login_history']
        )
        legitimate_scores.append(score)
    
    # Test anomaly samples
    for data in anomaly_data:
        score = model.predict_risk(
            {'timestamp': data['timestamp']},
            data['login_history']
        )
        anomaly_scores.append(score)
    
    logger.info(f"Legitimate scores - Mean: {np.mean(legitimate_scores):.2f}, "
                f"Std: {np.std(legitimate_scores):.2f}")
    logger.info(f"Anomaly scores - Mean: {np.mean(anomaly_scores):.2f}, "
                f"Std: {np.std(anomaly_scores):.2f}")
    
    # Test specific cases
    logger.info("\nTesting specific scenarios:")
    
    # Impossible travel test
    current_time = datetime.now()
    impossible_case = {
        'location': CITIES['London'],
        'timestamp': int(current_time.timestamp() * 1000),
        'login_history': [{
            'timestamp': int((current_time - timedelta(hours=1)).timestamp() * 1000),
            'location': {
                'latitude': CITIES['New York']['lat'],
                'longitude': CITIES['New York']['lon'],
                'city': 'New York',
                'country': CITIES['New York']['country']
            },
            'loginStatus': 'success'
        }]
    }
    
    score = model.predict_risk(
        {'timestamp': impossible_case['timestamp']},
        impossible_case['login_history']
    )
    logger.info(f"Impossible travel (NYC->London in 1hr): Risk score = {score}")


if __name__ == "__main__":
    main()