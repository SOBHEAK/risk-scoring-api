"""
Train DateTime Risk Model using synthetic data
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import random
from datetime import datetime, timedelta
from ml_models.datetime_model import DateTimeRiskModel
from config.settings import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_user_pattern():
    """Generate a realistic user login pattern"""
    patterns = [
        {
            'type': 'office_worker',
            'login_hours': list(range(8, 18)),  # 8 AM to 6 PM
            'login_days': list(range(0, 5)),    # Monday to Friday
            'frequency': 'daily'
        },
        {
            'type': 'remote_worker',
            'login_hours': list(range(7, 20)),  # 7 AM to 8 PM
            'login_days': list(range(0, 7)),    # All days
            'frequency': 'multiple_daily'
        },
        {
            'type': 'occasional_user',
            'login_hours': list(range(18, 23)),  # Evening user
            'login_days': list(range(0, 7)),     # Any day
            'frequency': 'weekly'
        },
        {
            'type': 'night_shift',
            'login_hours': list(range(20, 24)) + list(range(0, 6)),  # Night hours
            'login_days': list(range(0, 7)),
            'frequency': 'daily'
        }
    ]
    
    return random.choice(patterns)


def generate_legitimate_login_history(pattern, num_days=30):
    """Generate login history based on user pattern"""
    history = []
    current_time = datetime.now()
    
    for day in range(num_days):
        date = current_time - timedelta(days=day)
        
        # Skip some days based on frequency
        if pattern['frequency'] == 'weekly' and random.random() > 0.3:
            continue
        
        # Check if it's a valid login day
        if date.weekday() not in pattern['login_days'] and random.random() > 0.1:
            continue
        
        # Generate logins for this day
        if pattern['frequency'] == 'multiple_daily':
            num_logins = random.randint(2, 5)
        else:
            num_logins = 1
        
        for _ in range(num_logins):
            # Select hour from pattern with some variation
            hour = random.choice(pattern['login_hours'])
            if random.random() < 0.1:  # 10% chance of slight deviation
                hour = (hour + random.randint(-1, 1)) % 24
            
            minute = random.randint(0, 59)
            login_time = date.replace(hour=hour, minute=minute, second=0)
            
            history.append({
                'timestamp': int(login_time.timestamp() * 1000),
                'loginStatus': 'success' if random.random() > 0.02 else 'failure'
            })
    
    return sorted(history, key=lambda x: x['timestamp'], reverse=True)


def generate_training_data(num_samples=10000):
    """Generate synthetic training data for legitimate users"""
    training_data = []
    
    for i in range(num_samples):
        # Generate user pattern
        pattern = generate_user_pattern()
        
        # Generate login history
        login_history = generate_legitimate_login_history(pattern)
        
        # Create current session (following pattern)
        current_time = datetime.now()
        if current_time.weekday() in pattern['login_days']:
            hour = random.choice(pattern['login_hours'])
        else:
            hour = random.choice(pattern['login_hours']) if random.random() < 0.1 else current_time.hour
        
        current_time = current_time.replace(hour=hour, minute=random.randint(0, 59))
        
        session_data = {
            'timestamp': int(current_time.timestamp() * 1000),
            'login_history': login_history
        }
        
        training_data.append(session_data)
    
    return training_data


def generate_anomaly_data(num_samples=500):
    """Generate synthetic anomaly data"""
    anomaly_data = []
    
    anomaly_patterns = [
        'night_login',      # Login at unusual hours
        'rapid_attempts',   # Multiple rapid login attempts
        'timing_attack',    # Exact interval patterns
        'burst_activity'    # Sudden burst of activity
    ]
    
    for i in range(num_samples):
        pattern_type = random.choice(anomaly_patterns)
        current_time = datetime.now()
        login_history = []
        
        if pattern_type == 'night_login':
            # Normal history but current login at 3 AM
            normal_pattern = generate_user_pattern()
            login_history = generate_legitimate_login_history(normal_pattern, 20)
            current_time = current_time.replace(hour=3, minute=random.randint(0, 59))
            
        elif pattern_type == 'rapid_attempts':
            # Many attempts in short time
            base_time = current_time - timedelta(minutes=30)
            for j in range(20):
                attempt_time = base_time + timedelta(seconds=j * 30)
                login_history.append({
                    'timestamp': int(attempt_time.timestamp() * 1000),
                    'loginStatus': 'failure' if j < 15 else 'success'
                })
            
        elif pattern_type == 'timing_attack':
            # Exact intervals (bot behavior)
            interval = 300000  # 5 minutes
            for j in range(10):
                attempt_time = current_time - timedelta(milliseconds=j * interval)
                login_history.append({
                    'timestamp': int(attempt_time.timestamp() * 1000),
                    'loginStatus': 'success'
                })
            
        elif pattern_type == 'burst_activity':
            # Sudden activity after long inactivity
            # Old history
            old_time = current_time - timedelta(days=60)
            for j in range(5):
                login_history.append({
                    'timestamp': int((old_time - timedelta(days=j)).timestamp() * 1000),
                    'loginStatus': 'success'
                })
            # Recent burst
            for j in range(10):
                recent_time = current_time - timedelta(minutes=j * 5)
                login_history.append({
                    'timestamp': int(recent_time.timestamp() * 1000),
                    'loginStatus': 'success'
                })
        
        session_data = {
            'timestamp': int(current_time.timestamp() * 1000),
            'login_history': sorted(login_history, key=lambda x: x['timestamp'], reverse=True)
        }
        
        anomaly_data.append(session_data)
    
    return anomaly_data


def main():
    """Train the DateTime Risk Model"""
    logger.info("Generating training data...")
    
    # Generate legitimate data
    legitimate_data = generate_training_data(10000)
    logger.info(f"Generated {len(legitimate_data)} legitimate samples")
    
    # Initialize and train model
    model = DateTimeRiskModel(f"{settings.MODELS_PATH}/datetime_model.pkl")
    
    logger.info("Training DateTime Risk Model...")
    model.train(legitimate_data)
    
    # Save model
    os.makedirs(settings.MODELS_PATH, exist_ok=True)
    model.save_model()
    logger.info(f"Model saved to {settings.MODELS_PATH}/datetime_model.pkl")
    
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
    
    # Check separation
    if np.mean(anomaly_scores) > np.mean(legitimate_scores) + 20:
        logger.info("✓ Model shows good separation between normal and anomalous patterns")
    else:
        logger.warning("⚠ Model may need more tuning for better separation")


if __name__ == "__main__":
    main()