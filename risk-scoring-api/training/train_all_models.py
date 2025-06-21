# training/train_all_models.py
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from training.train_ip_model import train_ip_model
from training.train_datetime_model import train_datetime_model
from training.train_useragent_model import train_useragent_model
from training.train_geolocation_model import train_geolocation_model


def train_all_models():
    """Train all risk scoring models."""
    print("=" * 60)
    print("Training All Risk Scoring Models")
    print("=" * 60)
    
    # Create models directory
    os.makedirs("./models", exist_ok=True)
    
    # Train IP model
    print("\n" + "=" * 60)
    train_ip_model()
    
    # Train DateTime model
    print("\n" + "=" * 60)
    train_datetime_model()
    
    # Train UserAgent model
    print("\n" + "=" * 60)
    train_useragent_model()
    
    # Train Geolocation model
    print("\n" + "=" * 60)
    train_geolocation_model()
    
    print("\n" + "=" * 60)
    print("All models trained successfully!")
    print("Models saved in ./models directory")
    print("=" * 60)


if __name__ == "__main__":
    train_all_models()