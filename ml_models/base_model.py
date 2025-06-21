"""
Base class for all ML risk models
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import numpy as np
import joblib
import os
import logging

logger = logging.getLogger(__name__)


class BaseRiskModel(ABC):
    """Abstract base class for risk scoring models"""
    
    def __init__(self, model_name: str, model_path: str = None):
        self.model_name = model_name
        self.model_path = model_path
        self.model = None
        self.is_loaded = False
        
    @abstractmethod
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from input data"""
        pass
    
    @abstractmethod
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """Train the model on historical data"""
        pass
    
    @abstractmethod
    def predict_risk(self, current_session: Dict[str, Any], 
                    login_history: List[Dict[str, Any]] = None) -> int:
        """Predict risk score (0-100) for current session"""
        pass
    
    def save_model(self, path: str = None) -> None:
        """Save trained model to disk"""
        save_path = path or self.model_path
        if not save_path:
            raise ValueError("No save path specified")
            
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump(self.model, save_path)
        logger.info(f"Model {self.model_name} saved to {save_path}")
    
    def load_model(self, path: str = None) -> None:
        """Load trained model from disk"""
        load_path = path or self.model_path
        if not load_path:
            raise ValueError("No load path specified")
            
        if not os.path.exists(load_path):
            raise FileNotFoundError(f"Model file not found: {load_path}")
            
        self.model = joblib.load(load_path)
        self.is_loaded = True
        logger.info(f"Model {self.model_name} loaded from {load_path}")
    
    def normalize_score(self, raw_score: float, min_val: float = -1.0, 
                       max_val: float = 1.0) -> int:
        """Normalize raw model output to 0-100 risk score"""
        # Clamp the score
        raw_score = max(min_val, min(raw_score, max_val))
        
        # Normalize to 0-1
        normalized = (raw_score - min_val) / (max_val - min_val)
        
        # Convert to 0-100
        return int(normalized * 100)
    
    def calculate_anomaly_score(self, distance: float, threshold: float) -> int:
        """Convert anomaly distance to risk score"""
        if distance <= threshold:
            # Normal behavior
            return int(30 * (distance / threshold))
        else:
            # Anomalous behavior
            excess = distance - threshold
            score = 30 + int(70 * (1 - np.exp(-excess)))
            return min(100, score)