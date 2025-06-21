"""
Master training script to train all models
"""
import os
import sys
import logging
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def train_all_models():
    """Train all risk scoring models"""
    logger.info("Starting model training process...")
    start_time = datetime.now()
    
    # Import and run each training script
    try:
        # Train IP Model
        logger.info("Training IP Risk Model...")
        from training.train_ip_model import main as train_ip
        train_ip()
        logger.info("✓ IP Model trained successfully")
        
        # Train DateTime Model
        logger.info("Training DateTime Risk Model...")
        from training.train_datetime_model import main as train_datetime
        train_datetime()
        logger.info("✓ DateTime Model trained successfully")
        
        # Train UserAgent Model
        logger.info("Training UserAgent Risk Model...")
        from training.train_useragent_model import main as train_useragent
        train_useragent()
        logger.info("✓ UserAgent Model trained successfully")
        
        # Train Geolocation Model
        logger.info("Training Geolocation Risk Model...")
        from training.train_geolocation_model import main as train_geolocation
        train_geolocation()
        logger.info("✓ Geolocation Model trained successfully")
        
        # Calculate total time
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info(f"\n{'='*50}")
        logger.info(f"All models trained successfully!")
        logger.info(f"Total training time: {duration:.2f} seconds")
        logger.info(f"Models saved in: /app/ml_models/trained_models/")
        logger.info(f"{'='*50}\n")
        
        # List trained models
        model_dir = "/app/ml_models/trained_models"
        if os.path.exists(model_dir):
            models = os.listdir(model_dir)
            logger.info("Trained models:")
            for model in models:
                size = os.path.getsize(os.path.join(model_dir, model)) / 1024
                logger.info(f"  - {model} ({size:.2f} KB)")
        
        return True
        
    except Exception as e:
        logger.error(f"Error during training: {str(e)}")
        logger.error(f"Training failed after {(datetime.now() - start_time).total_seconds():.2f} seconds")
        raise e


if __name__ == "__main__":
    train_all_models()