"""
Train IP Risk Model using synthetic data
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import random
from datetime import datetime, timedelta
from ml_models.ip_model import IPRiskModel
from config.settings import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_legitimate_ip():
    """Generate legitimate residential IP addresses"""
    # Common residential ISP ranges (simplified)
    residential_ranges = [
        (24, 255),   # Comcast
        (68, 255),   # Charter
        (71, 255),   # Verizon
        (73, 255),   # Comcast
        (76, 255),   # AT&T
        (98, 255),   # Cox
        (174, 255),  # Shaw
    ]
    
    first_octet, _ = random.choice(residential_ranges)
    return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def generate_training_data(num_samples=10000):
    """Generate synthetic training data for legitimate users"""
    training_data = []
    
    for i in range(num_samples):
        # Create user profile
        user_ips = [generate_legitimate_ip() for _ in range(random.randint(1, 3))]
        primary_ip = user_ips[0]
        
        # Generate login history
        login_history = []
        current_time = int(datetime.now().timestamp() * 1000)
        
        for j in range(random.randint(5, 20)):
            login_time = current_time - random.randint(0, 30 * 24 * 3600 * 1000)
            login_ip = random.choice(user_ips) if random.random() > 0.1 else generate_legitimate_ip()
            
            login_history.append({
                'ip': login_ip,
                'timestamp': login_time,
                'loginStatus': 'success' if random.random() > 0.05 else 'failure'
            })
        
        # Create current session
        session_data = {
            'ip': primary_ip if random.random() > 0.2 else random.choice(user_ips),
            'timestamp': current_time,
            'login_history': sorted(login_history, key=lambda x: x['timestamp'], reverse=True)
        }
        
        training_data.append(session_data)
    
    return training_data


def generate_anomaly_data(num_samples=500):
    """Generate synthetic anomaly data for testing"""
    anomaly_data = []
    
    # VPN/Proxy IPs
    vpn_ranges = ['104.', '172.', '162.', '198.']
    
    for i in range(num_samples):
        # Anomalous patterns
        pattern = random.choice(['vpn', 'rapid_change', 'datacenter', 'suspicious'])
        
        if pattern == 'vpn':
            # VPN IP
            prefix = random.choice(vpn_ranges)
            ip = f"{prefix}{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        elif pattern == 'rapid_change':
            # Rapid IP changes
            ips = [generate_legitimate_ip() for _ in range(10)]
            ip = random.choice(ips)
        else:
            # Datacenter IP
            ip = f"{random.choice([13, 52, 54])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        
        current_time = int(datetime.now().timestamp() * 1000)
        
        # Generate suspicious history
        login_history = []
        for j in range(20):
            login_time = current_time - j * 300000  # Every 5 minutes
            login_ip = generate_legitimate_ip() if pattern == 'rapid_change' else ip
            
            login_history.append({
                'ip': login_ip,
                'timestamp': login_time,
                'loginStatus': 'failure' if j % 3 == 0 else 'success'
            })
        
        session_data = {
            'ip': ip,
            'timestamp': current_time,
            'login_history': login_history
        }
        
        anomaly_data.append(session_data)
    
    return anomaly_data


def main():
    """Train the IP Risk Model"""
    logger.info("Generating training data...")
    
    # Generate legitimate data
    legitimate_data = generate_training_data(10000)
    logger.info(f"Generated {len(legitimate_data)} legitimate samples")
    
    # Initialize and train model
    model = IPRiskModel(f"{settings.MODELS_PATH}/ip_model.pkl")
    
    logger.info("Training IP Risk Model...")
    model.train(legitimate_data)
    
    # Save model
    os.makedirs(settings.MODELS_PATH, exist_ok=True)
    model.save_model()
    logger.info(f"Model saved to {settings.MODELS_PATH}/ip_model.pkl")
    
    # Test on anomalies
    logger.info("Testing on anomaly data...")
    anomaly_data = generate_anomaly_data(100)
    
    legitimate_scores = []
    anomaly_scores = []
    
    # Test legitimate samples
    for data in legitimate_data[:100]:
        score = model.predict_risk(
            {'ip': data['ip'], 'timestamp': data['timestamp']},
            data['login_history']
        )
        legitimate_scores.append(score)
    
    # Test anomaly samples
    for data in anomaly_data:
        score = model.predict_risk(
            {'ip': data['ip'], 'timestamp': data['timestamp']},
            data['login_history']
        )
        anomaly_scores.append(score)
    
    logger.info(f"Legitimate scores - Mean: {np.mean(legitimate_scores):.2f}, "
                f"Std: {np.std(legitimate_scores):.2f}")
    logger.info(f"Anomaly scores - Mean: {np.mean(anomaly_scores):.2f}, "
                f"Std: {np.std(anomaly_scores):.2f}")
    
    # Check separation
    if np.mean(anomaly_scores) > np.mean(legitimate_scores) + 20:
        logger.info("✓ Model shows good separation between legitimate and anomalous IPs")
    else:
        logger.warning("⚠ Model may need more tuning for better separation")


if __name__ == "__main__":
    main()