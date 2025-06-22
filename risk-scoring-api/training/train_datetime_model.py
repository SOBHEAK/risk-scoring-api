# training/train_datetime_model.py
import random
import numpy as np
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from ml_models.datetime_model import DateTimeRiskModel


def generate_datetime_training_data() -> Dict[str, List]:
    """Generate synthetic training data for datetime model."""
    
    normal_patterns = []
    anomalous_patterns = []
    
    # Define user behavior profiles
    user_profiles = [
        {
            'name': 'office_worker',
            'login_hours': list(range(8, 18)),  # 8 AM - 6 PM
            'login_days': [0, 1, 2, 3, 4],  # Monday-Friday
            'frequency': 5  # Logins per day
        },
        {
            'name': 'night_shift',
            'login_hours': list(range(20, 24)) + list(range(0, 6)),  # 8 PM - 6 AM
            'login_days': [0, 1, 2, 3, 4, 5],  # Monday-Saturday
            'frequency': 3
        },
        {
            'name': 'remote_worker',
            'login_hours': list(range(6, 22)),  # 6 AM - 10 PM
            'login_days': [0, 1, 2, 3, 4, 5, 6],  # All days
            'frequency': 8
        },
        {
            'name': 'occasional_user',
            'login_hours': list(range(9, 21)),  # 9 AM - 9 PM
            'login_days': [0, 1, 2, 3, 4, 5, 6],  # All days
            'frequency': 1  # Once every few days
        }
    ]
    
    # Generate normal patterns
    base_time = datetime.now(timezone.utc) - timedelta(days=90)
    
    for profile in user_profiles:
        for user_id in range(50):  # 50 users per profile
            history = []
            current_time = base_time
            
            # Generate login history
            for day in range(90):
                if current_time.weekday() in profile['login_days']:
                    # Generate logins for this day
                    num_logins = np.random.poisson(profile['frequency'])
                    
                    for _ in range(num_logins):
                        # Pick a random hour from profile
                        hour = random.choice(profile['login_hours'])
                        minute = random.randint(0, 59)
                        
                        login_time = current_time.replace(
                            hour=hour, 
                            minute=minute,
                            second=random.randint(0, 59)
                        )
                        
                        history.append({
                            'timestamp': int(login_time.timestamp() * 1000),
                            'status': 'success'
                        })
                
                current_time += timedelta(days=1)
            
            # Sort history by timestamp
            history.sort(key=lambda x: x['timestamp'])
            
            # Current login (normal pattern)
            if history:
                last_hour = datetime.fromtimestamp(
                    history[-1]['timestamp'] / 1000, 
                    tz=timezone.utc
                ).hour
                
                # Similar hour as usual
                new_hour = (last_hour + random.randint(-2, 2)) % 24
                new_time = datetime.now(timezone.utc).replace(
                    hour=new_hour,
                    minute=random.randint(0, 59)
                )
                
                normal_patterns.append({
                    'timestamp': int(new_time.timestamp() * 1000),
                    'history': history
                })
    
    # Generate anomalous patterns
    anomaly_types = [
        'midnight_login',  # Login at 2-4 AM
        'burst_attack',    # Many logins in short time
        'dormant_return',  # Login after long absence
        'rapid_frequency', # Unusually high frequency
    ]
    
    for anomaly_type in anomaly_types:
        for _ in range(50):
            if anomaly_type == 'midnight_login':
                # User normally logs in during day, now at night
                history = []
                for i in range(30):
                    day_time = base_time + timedelta(days=i*3)
                    day_time = day_time.replace(
                        hour=random.randint(9, 17),
                        minute=random.randint(0, 59)
                    )
                    history.append({
                        'timestamp': int(day_time.timestamp() * 1000),
                        'status': 'success'
                    })
                
                # Anomalous login at 3 AM
                anomaly_time = datetime.now(timezone.utc).replace(
                    hour=3,
                    minute=random.randint(0, 59)
                )
                
            elif anomaly_type == 'burst_attack':
                # Normal history
                history = []
                for i in range(20):
                    normal_time = base_time + timedelta(days=i*4)
                    normal_time = normal_time.replace(
                        hour=random.randint(8, 18),
                        minute=random.randint(0, 59)
                    )
                    history.append({
                        'timestamp': int(normal_time.timestamp() * 1000),
                        'status': 'success'
                    })
                
                # Add burst of failed attempts
                burst_start = datetime.now(timezone.utc) - timedelta(hours=1)
                for i in range(20):  # 20 attempts in 1 hour
                    burst_time = burst_start + timedelta(minutes=i*3)
                    history.append({
                        'timestamp': int(burst_time.timestamp() * 1000),
                        'status': 'failure'
                    })
                
                anomaly_time = datetime.now(timezone.utc)
                
            elif anomaly_type == 'dormant_return':
                # Old history
                history = []
                for i in range(10):
                    old_time = base_time - timedelta(days=180+i*5)
                    old_time = old_time.replace(
                        hour=random.randint(9, 17),
                        minute=random.randint(0, 59)
                    )
                    history.append({
                        'timestamp': int(old_time.timestamp() * 1000),
                        'status': 'success'
                    })
                
                # Login after 6 months
                anomaly_time = datetime.now(timezone.utc)
                
            else:  # rapid_frequency
                # Recent rapid logins
                history = []
                rapid_start = datetime.now(timezone.utc) - timedelta(days=1)
                for i in range(50):  # 50 logins in 24 hours
                    rapid_time = rapid_start + timedelta(minutes=i*30)
                    history.append({
                        'timestamp': int(rapid_time.timestamp() * 1000),
                        'status': 'success' if random.random() > 0.3 else 'failure'
                    })
                
                anomaly_time = datetime.now(timezone.utc)
            
            anomalous_patterns.append({
                'timestamp': int(anomaly_time.timestamp() * 1000),
                'history': history
            })
    
    return {
        'normal': normal_patterns,
        'anomalous': anomalous_patterns
    }


def train_datetime_model():
    """Train and save the datetime risk model."""
    print("Training DateTime Risk Model...")
    
    # Generate training data
    training_data = generate_datetime_training_data()
    
    # Initialize model
    model = DateTimeRiskModel()
    
    # Train model
    model.train(training_data)
    
    # Save model
    model.save_model()
    
    # Test the model
    print("\nTesting DateTime Risk Model:")
    
    # Test normal business hours login
    now = datetime.now(timezone.utc).replace(hour=14, minute=30)  # 2:30 PM
    test_normal = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': int(now.timestamp() * 1000)
    }
    
    # Normal history
    history = []
    for i in range(10):
        hist_time = now - timedelta(days=i+1)
        hist_time = hist_time.replace(hour=random.randint(13, 16))
        history.append({
            'ip': '192.168.1.1',
            'userAgent': 'Mozilla/5.0...',
            'timestamp': int(hist_time.timestamp() * 1000),
            'location': {'country': 'US', 'city': 'New York', 'latitude': 40.7, 'longitude': -74.0},
            'loginStatus': 'success'
        })
    
    score = model.predict(test_normal, history)
    print(f"Normal business hours login score: {score}")
    
    # Test midnight login
    midnight = datetime.now(timezone.utc).replace(hour=3, minute=15)  # 3:15 AM
    test_midnight = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': int(midnight.timestamp() * 1000)
    }
    score = model.predict(test_midnight, history)
    print(f"Midnight login score: {score}")
    
    # Test burst pattern
    burst_history = history.copy()
    burst_start = datetime.now(timezone.utc) - timedelta(minutes=30)
    for i in range(10):
        burst_time = burst_start + timedelta(minutes=i*3)
        burst_history.append({
            'ip': '192.168.1.1',
            'userAgent': 'Mozilla/5.0...',
            'timestamp': int(burst_time.timestamp() * 1000),
            'location': {'country': 'US', 'city': 'New York', 'latitude': 40.7, 'longitude': -74.0},
            'loginStatus': 'failure'
        })
    
    test_burst = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000)
    }
    score = model.predict(test_burst, burst_history)
    print(f"Burst pattern login score: {score}")
    
    print("\nDateTime Risk Model training complete!")


if __name__ == "__main__":
    train_datetime_model()