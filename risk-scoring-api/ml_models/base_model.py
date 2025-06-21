# ml_models/base_model.py
from abc import ABC, abstractmethod
import os
import joblib
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime


class BaseRiskModel(ABC):
    """Base class for all risk scoring models."""
    
    def __init__(self, model_name: str, version: str = "v1.0.0"):
        self.model_name = model_name
        self.version = version
        self.model = None
        self.is_loaded = False
        self.model_path = f"./models/{model_name}_{version}.pkl"
        
    @abstractmethod
    def extract_features(self, current_session: Dict, login_history: List[Dict]) -> np.ndarray:
        """Extract features for model prediction."""
        pass
    
    @abstractmethod
    def train(self, training_data: Any) -> None:
        """Train the model."""
        pass
    
    def predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """
        Predict risk score (0-100).
        
        Args:
            current_session: Current login session data
            login_history: Historical login data
            
        Returns:
            Risk score between 0 and 100
        """
        if not self.is_loaded:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Extract features
        features = self.extract_features(current_session, login_history)
        
        # Get prediction
        try:
            # Different models return different types of scores
            if hasattr(self.model, 'decision_function'):
                # For One-Class SVM, use decision function
                score = self.model.decision_function(features.reshape(1, -1))[0]
                # Convert to risk score (negative = anomaly = high risk)
                risk_score = self._normalize_score(-score, method='svm')
            elif hasattr(self.model, 'predict_proba'):
                # For models with probability
                proba = self.model.predict_proba(features.reshape(1, -1))[0]
                risk_score = int(proba[1] * 100) if len(proba) > 1 else 50
            elif hasattr(self.model, 'score_samples'):
                # For Isolation Forest
                score = self.model.score_samples(features.reshape(1, -1))[0]
                # Convert to risk score (negative = anomaly = high risk)
                risk_score = self._normalize_score(-score, method='isolation_forest')
            else:
                # For other models (like autoencoders)
                risk_score = self._calculate_risk_score(features)
            
            return max(0, min(100, risk_score))
            
        except Exception as e:
            print(f"Error in {self.model_name} prediction: {e}")
            return 50  # Default medium risk on error
    
    def _normalize_score(self, score: float, method: str = 'svm') -> int:
        """
        Normalize model scores to 0-100 risk score.
        
        Args:
            score: Raw model score
            method: Normalization method based on model type
            
        Returns:
            Risk score between 0 and 100
        """
        if method == 'svm':
            # For One-Class SVM, typical scores range from -5 to 5
            # More negative = more anomalous = higher risk
            normalized = (score + 5) / 10  # Convert to 0-1 range
            risk_score = int(normalized * 100)
        elif method == 'isolation_forest':
            # For Isolation Forest, scores typically range from -0.5 to 0.5
            # More negative = more anomalous = higher risk
            normalized = (score + 0.5)  # Convert to 0-1 range
            risk_score = int(normalized * 100)
        else:
            # Generic normalization
            risk_score = int(abs(score) * 100)
        
        return max(0, min(100, risk_score))
    
    def _calculate_risk_score(self, features: np.ndarray) -> int:
        """
        Calculate risk score for models without built-in scoring.
        
        Args:
            features: Feature array
            
        Returns:
            Risk score between 0 and 100
        """
        # Override in subclasses for specific implementations
        return 50
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save trained model to disk."""
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'version': self.version,
            'model_name': self.model_name,
            'timestamp': datetime.now().isoformat(),
        }
        
        joblib.dump(model_data, save_path)
        print(f"Model saved to {save_path}")
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model from disk."""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            print(f"Model file not found: {load_path}")
            return False
        
        try:
            model_data = joblib.load(load_path)
            self.model = model_data['model']
            self.version = model_data.get('version', 'unknown')
            self.is_loaded = True
            print(f"Model {self.model_name} loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance if available."""
        # Override in subclasses if model supports feature importance
        return None