# training/train_ip_model.py
import json
import random
from typing import Dict, List
from ml_models.ip_model import IPRiskModel


def generate_ip_training_data() -> Dict[str, List]:
    """Generate synthetic training data for IP model."""
    
    # Normal residential IP patterns
    normal_ips = []
    
    # Common residential IP ranges
    residential_ranges = [
        "192.168.{}.{}",  # Private networks
        "10.0.{}.{}",     # Private networks
        "172.16.{}.{}",   # Private networks
        "24.{}.{}.{}",    # Comcast
        "73.{}.{}.{}",    # Comcast
        "98.{}.{}.{}",    # AT&T
        "174.{}.{}.{}",   # Shaw
        "68.{}.{}.{}",    # Charter
        "71.{}.{}.{}",    # Verizon
        "108.{}.{}.{}",   # Verizon
    ]
    
    # Generate normal patterns
    for _ in range(1000):
        # Pick a random residential range
        template = random.choice(residential_ranges)
        
        # Generate IP
        if template.startswith(("192.168", "10.0", "172.16")):
            # Private IPs
            ip = template.format(
                random.randint(0, 255),
                random.randint(1, 254)
            )
        else:
            # Public residential IPs
            ip = template.format(
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 254)
            )
        
        # Create history for this "user"
        history = []
        if random.random() > 0.3:  # 70% have history
            # Same IP used before
            for _ in range(random.randint(1, 5)):
                history.append({
                    'ip': ip,
                    'timestamp': random.randint(1600000000000, 1700000000000)
                })
            
            # Sometimes different IPs from same range
            if random.random() > 0.5:
                similar_ip = template.format(
                    random.randint(1, 255),
                    random.randint(1, 255),
                    random.randint(1, 254)
                )
                history.append({
                    'ip': similar_ip,
                    'timestamp': random.randint(1600000000000, 1700000000000)
                })
        
        normal_ips.append({
            'ip': ip,
            'history': history
        })
    
    # Anomalous IP patterns (for reference, not training)
    anomalous_ips = []
    
    # Datacenter/VPN ranges
    suspicious_ranges = [
        "104.16.{}.{}",   # Cloudflare
        "172.64.{}.{}",   # Cloudflare
        "35.{}.{}.{}",    # AWS
        "52.{}.{}.{}",    # AWS
        "40.{}.{}.{}",    # Azure
        "185.{}.{}.{}",   # Common VPN
        "45.{}.{}.{}",    # Digital Ocean
        "138.{}.{}.{}",   # Digital Ocean
    ]
    
    # Tor exit nodes (simulated)
    tor_ranges = ["198.96.{}.{}", "199.87.{}.{}", "176.10.{}.{}", "46.165.{}.{}"]
    
    # Generate anomalous patterns
    for _ in range(200):
        if random.random() > 0.5:
            # Datacenter/VPN IP
            template = random.choice(suspicious_ranges)
        else:
            # Tor exit node
            template = random.choice(tor_ranges)
        
        if template.count('{}') == 2:
            ip = template.format(
                random.randint(1, 255),
                random.randint(1, 254)
            )
        else:  # 3 placeholders
            ip = template.format(
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 254)
            )
        
        anomalous_ips.append({
            'ip': ip,
            'history': []  # New IP, no history
        })
    
    return {
        'normal': normal_ips,
        'anomalous': anomalous_ips
    }


def train_ip_model():
    """Train and save the IP risk model."""
    print("Training IP Risk Model...")
    
    # Generate training data
    training_data = generate_ip_training_data()
    
    # Initialize model
    model = IPRiskModel()
    
    # Train model
    model.train(training_data)
    
    # Save model
    model.save_model()
    
    # Test the model
    print("\nTesting IP Risk Model:")
    
    # Test normal residential IP
    test_normal = {
        'ip': '73.123.45.67',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': 1703001600000
    }
    score = model.predict(test_normal, [])
    print(f"Normal residential IP score: {score}")
    
    # Test VPN/datacenter IP
    test_vpn = {
        'ip': '104.16.123.45',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': 1703001600000
    }
    score = model.predict(test_vpn, [])
    print(f"VPN/Datacenter IP score: {score}")
    
    # Test Tor exit node
    test_tor = {
        'ip': '198.96.155.3',
        'userAgent': 'Mozilla/5.0...',
        'timestamp': 1703001600000
    }
    score = model.predict(test_tor, [])
    print(f"Tor exit node IP score: {score}")
    
    print("\nIP Risk Model training complete!")


if __name__ == "__main__":
    train_ip_model()