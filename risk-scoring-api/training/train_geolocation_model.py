# training/train_geolocation_model.py
import random
from typing import Dict, List
from ml_models.geolocation_model import GeolocationRiskModel


def generate_geolocation_training_data() -> Dict[str, List]:
    """Generate synthetic training data for geolocation model."""
    
    # Major cities with coordinates
    cities = [
        # North America
        {'city': 'New York', 'country': 'United States', 'lat': 40.7128, 'lon': -74.0060},
        {'city': 'Los Angeles', 'country': 'United States', 'lat': 34.0522, 'lon': -118.2437},
        {'city': 'Chicago', 'country': 'United States', 'lat': 41.8781, 'lon': -87.6298},
        {'city': 'Toronto', 'country': 'Canada', 'lat': 43.6532, 'lon': -79.3832},
        {'city': 'Vancouver', 'country': 'Canada', 'lat': 49.2827, 'lon': -123.1207},
        {'city': 'Mexico City', 'country': 'Mexico', 'lat': 19.4326, 'lon': -99.1332},
        
        # Europe
        {'city': 'London', 'country': 'United Kingdom', 'lat': 51.5074, 'lon': -0.1278},
        {'city': 'Paris', 'country': 'France', 'lat': 48.8566, 'lon': 2.3522},
        {'city': 'Berlin', 'country': 'Germany', 'lat': 52.5200, 'lon': 13.4050},
        {'city': 'Madrid', 'country': 'Spain', 'lat': 40.4168, 'lon': -3.7038},
        {'city': 'Rome', 'country': 'Italy', 'lat': 41.9028, 'lon': 12.4964},
        {'city': 'Amsterdam', 'country': 'Netherlands', 'lat': 52.3676, 'lon': 4.9041},
        
        # Asia
        {'city': 'Tokyo', 'country': 'Japan', 'lat': 35.6762, 'lon': 139.6503},
        {'city': 'Shanghai', 'country': 'China', 'lat': 31.2304, 'lon': 121.4737},
        {'city': 'Singapore', 'country': 'Singapore', 'lat': 1.3521, 'lon': 103.8198},
        {'city': 'Mumbai', 'country': 'India', 'lat': 19.0760, 'lon': 72.8777},
        {'city': 'Seoul', 'country': 'South Korea', 'lat': 37.5665, 'lon': 126.9780},
        
        # Australia
        {'city': 'Sydney', 'country': 'Australia', 'lat': -33.8688, 'lon': 151.2093},
        {'city': 'Melbourne', 'country': 'Australia', 'lat': -37.8136, 'lon': 144.9631},
        
        # South America
        {'city': 'São Paulo', 'country': 'Brazil', 'lat': -23.5505, 'lon': -46.6333},
        {'city': 'Buenos Aires', 'country': 'Argentina', 'lat': -34.6037, 'lon': -58.3816},
    ]
    
    # Generate location clusters (users typically login from same areas)
    location_data = []
    
    # Generate clusters of normal behavior
    num_clusters = 50
    for cluster_id in range(num_clusters):
        # Pick a center city
        center = random.choice(cities)
        
        # Generate points around this center (within ~100km)
        cluster_points = []
        for _ in range(random.randint(20, 50)):
            # Add some noise to coordinates (roughly 1 degree = 111km)
            lat_noise = random.uniform(-0.9, 0.9)
            lon_noise = random.uniform(-0.9, 0.9)
            
            point = {
                'latitude': center['lat'] + lat_noise,
                'longitude': center['lon'] + lon_noise,
                'city': center['city'],
                'country': center['country']
            }
            cluster_points.append(point)
        
        location_data.extend(cluster_points)
    
    # Add some isolated points (travelers, remote users)
    for _ in range(100):
        city = random.choice(cities)
        location_data.append({
            'latitude': city['lat'] + random.uniform(-0.1, 0.1),
            'longitude': city['lon'] + random.uniform(-0.1, 0.1),
            'city': city['city'],
            'country': city['country']
        })
    
    return {
        'locations': location_data
    }


def generate_test_scenarios():
    """Generate test scenarios for geolocation model."""
    
    # Normal scenario: User in New York
    normal_history = []
    base_timestamp = 1700000000000
    
    for i in range(10):
        normal_history.append({
            'ip': '73.123.45.67',
            'userAgent': 'Mozilla/5.0...',
            'timestamp': base_timestamp + (i * 86400000),  # Daily logins
            'location': {
                'country': 'United States',
                'city': 'New York',
                'latitude': 40.7128 + random.uniform(-0.1, 0.1),
                'longitude': -74.0060 + random.uniform(-0.1, 0.1)
            },
            'loginStatus': 'success'
        })
    
    # Impossible travel scenario: NYC to London in 1 hour
    impossible_history = normal_history.copy()
    impossible_history.append({
        'ip': '185.123.45.67',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': base_timestamp + (11 * 86400000),  # 11 days later
        'location': {
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        },
        'loginStatus': 'success'
    })
    
    # Country hopping scenario
    hopping_history = []
    countries = [
        {'country': 'United States', 'city': 'New York', 'lat': 40.7128, 'lon': -74.0060},
        {'country': 'China', 'city': 'Shanghai', 'lat': 31.2304, 'lon': 121.4737},
        {'country': 'Russia', 'city': 'Moscow', 'lat': 55.7558, 'lon': 37.6173},
        {'country': 'Brazil', 'city': 'São Paulo', 'lat': -23.5505, 'lon': -46.6333},
        {'country': 'Nigeria', 'city': 'Lagos', 'lat': 6.5244, 'lon': 3.3792},
    ]
    
    for i, location in enumerate(countries):
        hopping_history.append({
            'ip': f'185.{i}.45.67',
            'userAgent': 'Mozilla/5.0...',
            'timestamp': base_timestamp + (i * 86400000),
            'location': {
                'country': location['country'],
                'city': location['city'],
                'latitude': location['lat'],
                'longitude': location['lon']
            },
            'loginStatus': 'success'
        })
    
    return {
        'normal': (normal_history, 'United States', 'New York'),
        'impossible': (impossible_history, 'United Kingdom', 'London'),
        'hopping': (hopping_history, 'Iran', 'Tehran')
    }


def train_geolocation_model():
    """Train and save the geolocation risk model."""
    print("Training Geolocation Risk Model...")
    
    # Generate training data
    training_data = generate_geolocation_training_data()
    
    # Initialize model
    model = GeolocationRiskModel()
    
    # Train model
    model.train(training_data)
    
    # Save model
    model.save_model()
    
    # Test the model
    print("\nTesting Geolocation Risk Model:")
    
    test_scenarios = generate_test_scenarios()
    
    # Test normal scenario
    history, country, city = test_scenarios['normal']
    test_normal = {
        'ip': '73.123.45.68',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': 1703001600000
    }
    # Simulate location for current session
    model._get_current_location = lambda x, y: {
        'country': country,
        'city': city,
        'latitude': 40.7128 + random.uniform(-0.05, 0.05),
        'longitude': -74.0060 + random.uniform(-0.05, 0.05)
    }
    score = model.predict(test_normal, history)
    print(f"Normal location (same city) score: {score}")
    
    # Test impossible travel
    history, country, city = test_scenarios['impossible']
    test_impossible = {
        'ip': '185.123.45.67',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': history[-1]['timestamp'] + 3600000  # 1 hour later
    }
    model._get_current_location = lambda x, y: {
        'country': country,
        'city': city,
        'latitude': 51.5074,
        'longitude': -0.1278
    }
    score = model.predict(test_impossible, history)
    print(f"Impossible travel (NYC to London in 1 hour) score: {score}")
    
    # Test country hopping
    history, country, city = test_scenarios['hopping']
    test_hopping = {
        'ip': '185.99.45.67',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': 1703001600000
    }
    model._get_current_location = lambda x, y: {
        'country': country,
        'city': city,
        'latitude': 35.6892,
        'longitude': 51.3890
    }
    score = model.predict(test_hopping, history)
    print(f"Country hopping (5 countries + Iran) score: {score}")
    
    print("\nGeolocation Risk Model training complete!")


if __name__ == "__main__":
    train_geolocation_model()