"""
UserAgent Risk Model using Autoencoder (Neural Network)
Detects: Bots, headless browsers, spoofed agents, malware
"""
import numpy as np
from typing import Dict, Any, List
import re
import logging
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from user_agents import parse

from ml_models.base_model import BaseRiskModel

logger = logging.getLogger(__name__)


class UserAgentRiskModel(BaseRiskModel):
    """Autoencoder model for UserAgent anomaly detection"""
    
    def __init__(self, model_path: str = None):
        super().__init__("UserAgent Risk Model", model_path)
        self.scaler = StandardScaler()
        self.encoding_dim = 16
        self.input_dim = 25
        
        # Known bot patterns
        self.bot_patterns = [
            r'bot', r'crawler', r'spider', r'scraper', r'wget', r'curl',
            r'python', r'java', r'perl', r'ruby', r'headless', r'phantom',
            r'selenium', r'puppeteer', r'playwright'
        ]
        
        # Known browser versions that are outdated/suspicious
        self.outdated_browsers = {
            'Chrome': 80,  # Versions below 80 are outdated
            'Firefox': 75,
            'Safari': 13,
            'Edge': 80
        }
        
    def build_autoencoder(self):
        """Build the autoencoder architecture"""
        # Encoder
        input_layer = keras.Input(shape=(self.input_dim,))
        encoded = layers.Dense(64, activation='relu')(input_layer)
        encoded = layers.Dense(32, activation='relu')(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(32, activation='relu')(encoded)
        decoded = layers.Dense(64, activation='relu')(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # Create model
        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract UserAgent-based features"""
        user_agent_str = data.get('userAgent', '')
        current_session = data.get('currentSession', {})
        
        features = []
        
        try:
            # Parse user agent
            ua = parse(user_agent_str)
            
            # Browser features
            features.append(1 if ua.is_mobile else 0)
            features.append(1 if ua.is_tablet else 0)
            features.append(1 if ua.is_pc else 0)
            features.append(1 if ua.is_bot else 0)
            
            # Browser family encoding (one-hot simplified)
            browser_families = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera']
            for family in browser_families:
                features.append(1 if family in ua.browser.family else 0)
            
            # OS family encoding
            os_families = ['Windows', 'Mac', 'Linux', 'Android', 'iOS']
            for os_fam in os_families:
                features.append(1 if os_fam in ua.os.family else 0)
            
            # Version consistency check
            try:
                major_version = int(ua.browser.version_string.split('.')[0])
                features.append(major_version / 100.0)  # Normalize
            except:
                features.append(0.5)
            
            # Check for bot patterns
            ua_lower = user_agent_str.lower()
            bot_score = sum(1 for pattern in self.bot_patterns 
                          if re.search(pattern, ua_lower))
            features.append(min(bot_score / 5.0, 1.0))  # Normalize
            
            # Length features
            features.append(len(user_agent_str) / 500.0)  # Normalize
            
            # Additional session features if available
            if current_session:
                # Touch support vs mobile detection
                touch = current_session.get('touchSupport', False)
                features.append(1 if touch and not ua.is_mobile else 0)
                
                # Hardware concurrency check
                cores = current_session.get('hardwareConcurrency', 4)
                features.append(cores / 16.0)  # Normalize
                
                # Canvas fingerprint presence
                features.append(1 if current_session.get('canvasFingerprint') else 0)
                
                # Plugins count (bots often have 0)
                plugins = len(current_session.get('plugins', []))
                features.append(min(plugins / 10.0, 1.0))
                
                # Cookie/Java enabled
                features.append(1 if current_session.get('isCookieEnabled', True) else 0)
                features.append(1 if current_session.get('isJavaEnabled', False) else 0)
            else:
                features.extend([0] * 6)
                
            # Pad to ensure consistent size
            while len(features) < self.input_dim:
                features.append(0)
                
        except Exception as e:
            logger.error(f"Error extracting UserAgent features: {e}")
            features = [0.5] * self.input_dim
            
        return np.array(features[:self.input_dim]).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """Train the autoencoder on legitimate UserAgent data"""
        logger.info("Training UserAgent Risk Model...")
        
        # Extract features
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features[0])
        
        X = np.array(X)
        
        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Build and train autoencoder
        self.model = self.build_autoencoder()
        
        # Train
        history = self.model.fit(
            X_scaled, X_scaled,
            epochs=50,
            batch_size=32,
            shuffle=True,
            validation_split=0.1,
            verbose=1
        )
        
        # Calculate reconstruction threshold
        predictions = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
        
        logger.info(f"UserAgent model trained on {len(X)} samples, threshold: {self.threshold}")
    
    def predict_risk(self, current_session: Dict[str, Any], 
                    login_history: List[Dict[str, Any]] = None) -> int:
        """Predict risk score for current UserAgent"""
        if not self.is_loaded and self.model is None:
            logger.warning("Model not loaded, returning default score")
            return 50
        
        try:
            # Prepare data
            data = {
                'userAgent': current_session.get('userAgent', ''),
                'currentSession': current_session
            }
            
            # Extract features
            features = self.extract_features(data)
            features_scaled = self.scaler.transform(features)
            
            # Get reconstruction error
            prediction = self.model.predict(features_scaled)
            mse = np.mean(np.power(features_scaled - prediction, 2))
            
            # Base risk from reconstruction error
            if mse <= self.threshold:
                base_risk = int(30 * (mse / self.threshold))
            else:
                excess = mse - self.threshold
                base_risk = 30 + int(70 * (1 - np.exp(-excess * 5)))
            
            base_risk = max(0, min(100, base_risk))
            
            # Additional checks
            ua_str = current_session.get('userAgent', '').lower()
            ua = parse(current_session.get('userAgent', ''))
            
            # Direct bot detection
            if ua.is_bot:
                base_risk = max(base_risk, 80)
            
            # Headless browser detection
            if any(pattern in ua_str for pattern in ['headless', 'phantom', 'selenium']):
                base_risk = max(base_risk, 85)
            
            # Puppeteer detection
            if 'puppeteer' in ua_str or 'HeadlessChrome' in ua_str:
                base_risk = max(base_risk, 90)
            
            # Check for outdated browsers
            try:
                browser_family = ua.browser.family
                major_version = int(ua.browser.version_string.split('.')[0])
                
                if browser_family in self.outdated_browsers:
                    if major_version < self.outdated_browsers[browser_family]:
                        base_risk = min(100, base_risk + 20)
            except:
                pass
            
            # Empty or too short user agent
            if len(ua_str) < 20:
                base_risk = max(base_risk, 75)
            
            # Check for impossible combinations
            if current_session.get('touchSupport') and 'Windows NT' in ua_str and 'Mobile' not in ua_str:
                # Touch support on non-mobile Windows is suspicious
                base_risk = min(100, base_risk + 15)
            
            # Check consistency with history
            if login_history:
                # Count different user agents
                user_agents = set(item.get('userAgent', '') for item in login_history[-10:])
                if len(user_agents) > 5:  # Too many different agents
                    base_risk = min(100, base_risk + 10)
            
            return base_risk
            
        except Exception as e:
            logger.error(f"Error in UserAgent risk prediction: {e}")
            return 50