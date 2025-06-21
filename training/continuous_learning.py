"""
Continuous Learning Pipeline for Risk Models
Retrains models based on feedback and new patterns
"""
import sys
import os

from api.main import get_mongodb_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import numpy as np
from typing import List, Dict, Any
import logging
import schedule
import time

from ml_models.ip_model import IPRiskModel
from ml_models.datetime_model import DateTimeRiskModel
from ml_models.useragent_model import UserAgentRiskModel
from ml_models.geolocation_model import GeolocationRiskModel
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ContinuousLearningPipeline:
    """Manages continuous learning for all risk models"""
    
    def __init__(self):
        self.mongodb_url = settings.MONGODB_URL
        self.db_name = settings.MONGODB_DB_NAME
        self.models = {
            'ip': IPRiskModel(f"{settings.MODELS_PATH}/ip_model.pkl"),
            'datetime': DateTimeRiskModel(f"{settings.MODELS_PATH}/datetime_model.pkl"),
            'useragent': UserAgentRiskModel(f"{settings.MODELS_PATH}/useragent_model.pkl"),
            'geolocation': GeolocationRiskModel(f"{settings.MODELS_PATH}/geolocation_model.pkl")
        }
        
    async def get_labeled_data(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Fetch labeled data from MongoDB"""
        client = AsyncIOMotorClient(self.mongodb_url)
        db = client[self.db_name]
        
        # Calculate cutoff timestamp
        cutoff_date = datetime.now() - timedelta(days=days_back)
        cutoff_timestamp = int(cutoff_date.timestamp() * 1000)
        
        # Fetch data with feedback
        cursor = db.risk_scores.find({
            'timestamp': {'$gte': cutoff_timestamp},
            'decision_feedback': {'$exists': True, '$ne': None}
        })
        
        labeled_data = []
        async for doc in cursor:
            labeled_data.append(doc)
            
        logger.info(f"Fetched {len(labeled_data)} labeled samples from last {days_back} days")
        return labeled_data
    
    async def get_high_confidence_data(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch high-confidence predictions for semi-supervised learning"""
        client = AsyncIOMotorClient(self.mongodb_url)
        db = client[self.db_name]
        
        cutoff_date = datetime.now() - timedelta(days=days_back)
        cutoff_timestamp = int(cutoff_date.timestamp() * 1000)
        
        # Get very low risk scores (likely legitimate)
        legitimate_cursor = db.risk_scores.find({
            'timestamp': {'$gte': cutoff_timestamp},
            'scores.overall': {'$lte': 20},
            'decision_feedback': None
        }).limit(1000)
        
        # Get very high risk scores (likely attacks)
        attack_cursor = db.risk_scores.find({
            'timestamp': {'$gte': cutoff_timestamp},
            'scores.overall': {'$gte': 85},
            'decision_feedback': None
        }).limit(100)
        
        high_confidence_data = []
        
        async for doc in legitimate_cursor:
            doc['inferred_label'] = 'legitimate'
            high_confidence_data.append(doc)
            
        async for doc in attack_cursor:
            doc['inferred_label'] = 'suspicious'
            high_confidence_data.append(doc)
            
        logger.info(f"Fetched {len(high_confidence_data)} high-confidence samples")
        return high_confidence_data
    
    def prepare_training_data(self, raw_data: List[Dict[str, Any]]) -> Dict[str, List]:
        """Prepare data for model retraining"""
        training_data = {
            'ip': [],
            'datetime': [],
            'useragent': [],
            'geolocation': []
        }
        
        for doc in raw_data:
            # Determine if legitimate based on feedback or inference
            is_legitimate = False
            if 'decision_feedback' in doc and doc['decision_feedback']:
                is_legitimate = doc['decision_feedback'].get('was_legitimate', False)
            elif 'inferred_label' in doc:
                is_legitimate = doc['inferred_label'] == 'legitimate'
            
            # Only train on legitimate samples (One-Class algorithms)
            if is_legitimate:
                session_data = doc.get('session_data', {})
                
                # Prepare data for each model
                training_data['ip'].append({
                    'ip': session_data.get('ip'),
                    'timestamp': session_data.get('timestamp'),
                    'login_history': []  # Would need to fetch from user history
                })
                
                training_data['datetime'].append({
                    'timestamp': session_data.get('timestamp'),
                    'login_history': []
                })
                
                training_data['useragent'].append({
                    'userAgent': session_data.get('userAgent'),
                    'currentSession': session_data
                })
                
                training_data['geolocation'].append({
                    'location': doc.get('location'),
                    'timestamp': session_data.get('timestamp'),
                    'login_history': []
                })
        
        return training_data
    
    async def update_models(self):
        """Main continuous learning update process"""
        logger.info("Starting continuous learning update...")
        
        try:
            # 1. Fetch labeled data (ground truth)
            labeled_data = await self.get_labeled_data(days_back=7)
            
            # 2. Fetch high-confidence data (semi-supervised)
            high_confidence_data = await self.get_high_confidence_data(days_back=30)
            
            # 3. Combine data
            all_training_data = labeled_data + high_confidence_data
            
            if len(all_training_data) < 100:
                logger.warning(f"Not enough data for retraining: {len(all_training_data)} samples")
                return
            
            # 4. Prepare data for each model
            training_datasets = self.prepare_training_data(all_training_data)
            
            # 5. Retrain each model incrementally
            for model_name, model in self.models.items():
                dataset = training_datasets[model_name]
                
                if len(dataset) > 50:  # Minimum samples for retraining
                    logger.info(f"Retraining {model_name} model with {len(dataset)} samples...")
                    
                    # Load existing model
                    model.load_model()
                    
                    # Incremental training (mixing old + new data)
                    model.train(dataset)
                    
                    # Save updated model with versioning
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = f"{settings.MODELS_PATH}/{model_name}_model_backup_{timestamp}.pkl"
                    
                    # Backup current model
                    os.rename(
                        f"{settings.MODELS_PATH}/{model_name}_model.pkl",
                        backup_path
                    )
                    
                    # Save new model
                    model.save_model()
                    
                    logger.info(f"{model_name} model updated successfully")
                else:
                    logger.info(f"Skipping {model_name} model - insufficient data")
            
            # 6. Update model version in settings
            await self.update_model_version()
            
            logger.info("Continuous learning update completed!")
            
        except Exception as e:
            logger.error(f"Error in continuous learning: {e}")
    
    async def update_model_version(self):
        """Update model version after retraining"""
        client = AsyncIOMotorClient(self.mongodb_url)
        db = client[self.db_name]
        
        version_info = {
            'version': f"v1.{datetime.now().strftime('%Y%m%d.%H%M')}",
            'updated_at': datetime.now(),
            'models_updated': list(self.models.keys())
        }
        
        await db.model_versions.insert_one(version_info)
        logger.info(f"Model version updated to {version_info['version']}")
    
    def detect_drift(self) -> Dict[str, float]:
        """Detect model drift by comparing recent predictions"""
        # This would compare:
        # 1. Distribution of risk scores over time
        # 2. Feature distributions
        # 3. Prediction confidence
        # 4. False positive/negative rates
        
        drift_scores = {
            'ip': 0.0,
            'datetime': 0.0,
            'useragent': 0.0,
            'geolocation': 0.0
        }
        
        # Implement drift detection logic here
        # High drift score = model needs retraining
        
        return drift_scores


# Feedback API endpoint to add to main.py
async def submit_feedback(request_id: str, was_legitimate: bool, notes: str = ""):
    """Submit feedback for a risk assessment"""
    db = await get_mongodb_client()
    
    feedback = {
        'was_legitimate': was_legitimate,
        'feedback_time': datetime.now(),
        'notes': notes
    }
    
    result = await db.risk_scores.update_one(
        {'request_id': request_id},
        {'$set': {'decision_feedback': feedback}}
    )
    
    return {"updated": result.modified_count > 0}


def run_continuous_learning():
    """Run continuous learning on schedule"""
    pipeline = ContinuousLearningPipeline()
    
    # Schedule daily retraining at 2 AM
    schedule.every().day.at("02:00").do(
        lambda: asyncio.run(pipeline.update_models())
    )
    
    # Schedule drift detection every 6 hours
    schedule.every(6).hours.do(
        lambda: pipeline.detect_drift()
    )
    
    logger.info("Continuous learning scheduler started")
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute


if __name__ == "__main__":
    # For testing
    pipeline = ContinuousLearningPipeline()
    asyncio.run(pipeline.update_models())