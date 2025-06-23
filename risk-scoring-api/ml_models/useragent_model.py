# ml_models/useragent_model.py
import os
import joblib
import numpy as np
from typing import Dict, List, Optional
import tensorflow as tf
from tensorflow.keras import layers, models
from sklearn.preprocessing import StandardScaler
from ml_models.base_model import BaseRiskModel
from utils.feature_extractors import extract_user_agent_features


class UserAgentRiskModel(BaseRiskModel):
    """
    UserAgent Risk Model using Autoencoder Neural Network.
    Detects bots, headless browsers, spoofed agents, and malware.
    """
    
    def __init__(self, version: str = "v1.0.0"):
        super().__init__("useragent_risk_model", version)
        self.scaler = StandardScaler()
        self.encoder = None
        self.threshold = None
        self.feature_names = [
            'ua_length', 'is_bot', 'is_mobile', 'is_tablet', 'is_pc',
            'browser_chrome', 'browser_firefox', 'browser_safari', 'browser_edge',
            'os_windows', 'os_mac', 'os_linux', 'os_android', 'os_ios',
            'is_suspicious', 'entropy', 'has_version', 'special_char_ratio'
        ]
    
    def extract_features(self, current_session: Dict, login_history: List[Dict]) -> np.ndarray:
        """Extract user agent features."""
        user_agent = current_session['userAgent']
        
        # Get basic features
        features = extract_user_agent_features(user_agent)
        
        # One-hot encode browser family
        browser_features = {
            'browser_chrome': features['browser_family'].lower() == 'chrome',
            'browser_firefox': features['browser_family'].lower() == 'firefox',
            'browser_safari': features['browser_family'].lower() == 'safari',
            'browser_edge': features['browser_family'].lower() == 'edge',
        }
        
        # One-hot encode OS family
        os_features = {
            'os_windows': 'windows' in features['os_family'].lower(),
            'os_mac': 'mac' in features['os_family'].lower(),
            'os_linux': 'linux' in features['os_family'].lower(),
            'os_android': 'android' in features['os_family'].lower(),
            'os_ios': 'ios' in features['os_family'].lower(),
        }
        
        # Additional features
        has_version = features['browser_version'] != 'unknown'
        special_char_ratio = len([c for c in user_agent if not c.isalnum()]) / max(len(user_agent), 1)
        
        # Create feature vector
        feature_vector = [
            min(features['length'] / 500, 1),  # Normalize length
            float(features['is_bot']),
            float(features['is_mobile']),
            float(features['is_tablet']),
            float(features['is_pc']),
            float(browser_features['browser_chrome']),
            float(browser_features['browser_firefox']),
            float(browser_features['browser_safari']),
            float(browser_features['browser_edge']),
            float(os_features['os_windows']),
            float(os_features['os_mac']),
            float(os_features['os_linux']),
            float(os_features['os_android']),
            float(os_features['os_ios']),
            float(features['is_suspicious']),
            features['entropy'] / 5,  # Normalize entropy (typical range 0-5)
            float(has_version),
            special_char_ratio
        ]
        
        return np.array(feature_vector)
    
    def _build_autoencoder(self, input_dim: int) -> tf.keras.Model:
        """Build autoencoder architecture."""
        # Encoder
        encoder_input = layers.Input(shape=(input_dim,))
        encoded = layers.Dense(12, activation='relu')(encoder_input)
        encoded = layers.Dense(8, activation='relu')(encoded)
        encoded = layers.Dense(4, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(8, activation='relu')(encoded)
        decoded = layers.Dense(12, activation='relu')(decoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = models.Model(encoder_input, decoded)
        
        # Encoder model (for getting encodings)
        self.encoder = models.Model(encoder_input, encoded)
        
        return autoencoder
    
    def train(self, training_data: Dict) -> None:
        """
        Train the Autoencoder model.
        
        Args:
            training_data: Dictionary with 'normal' and 'anomalous' user agents
        """
        # Extract features for normal user agents
        normal_features = []
        for ua_data in training_data['normal']:
            features = self.extract_features(
                {'userAgent': ua_data['userAgent']},
                ua_data.get('history', [])
            )
            normal_features.append(features)
        
        X_train = np.array(normal_features)
        
        # Fit scaler
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        
        # Build and compile autoencoder
        input_dim = X_train_scaled.shape[1]
        self.model = self._build_autoencoder(input_dim)
        self.model.compile(
            optimizer='adam',
            loss='mse',  # This needs to be a string, not a function reference
            metrics=['mae']
        )
        
        # Train autoencoder
        history = self.model.fit(
            X_train_scaled, X_train_scaled,
            epochs=50,
            batch_size=32,
            validation_split=0.1,
            shuffle=True,
            verbose=0
        )
        
        # Calculate threshold based on training data reconstruction error
        train_predictions = self.model.predict(X_train_scaled, verbose=0)
        mse = np.mean(np.power(X_train_scaled - train_predictions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
        
        self.is_loaded = True
        print(f"UserAgent Risk Model trained with {len(X_train)} samples")
    
    def _calculate_risk_score(self, features: np.ndarray) -> int:
        """Calculate risk score based on reconstruction error."""
        # Scale features
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get reconstruction
        reconstruction = self.model.predict(features_scaled, verbose=0)
        
        # Calculate reconstruction error
        mse = np.mean(np.power(features_scaled - reconstruction, 2))
        
        # Convert to risk score
        if self.threshold is not None:
            # Score based on how much the error exceeds the threshold
            if mse <= self.threshold:
                risk = int((mse / self.threshold) * 30)  # 0-30 for normal
            else:
                # Scale 30-100 based on how much it exceeds threshold
                excess_ratio = (mse - self.threshold) / self.threshold
                risk = 30 + int(min(excess_ratio * 35, 70))  # 30-100 for anomalous
        else:
            # Fallback if threshold not set
            risk = int(min(mse * 100, 100))
        
        return risk
    
    def predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Override predict to use autoencoder reconstruction error."""
        if not self.is_loaded:
            # Use rule-based fallback
            return self._fallback_predict(current_session, login_history)
        
        # Extract features
        features = self.extract_features(current_session, login_history)
        
        # Get base risk from autoencoder
        base_risk = self._calculate_risk_score(features)
        
        # Apply rules-based adjustments
        risk_adjustments = self._apply_risk_rules(current_session)
        
        # Combine risks
        final_risk = base_risk + risk_adjustments
        
        return max(0, min(100, final_risk))
    
    def _fallback_predict(self, current_session: Dict, login_history: List[Dict]) -> int:
        """Fallback prediction when model not loaded."""
        user_agent = current_session['userAgent']
        features = extract_user_agent_features(user_agent)
        
        risk = 0
        
        # Bot detection
        if features['is_bot']:
            risk += 80
        
        # Suspicious UA
        if features['is_suspicious']:
            risk += 40
        
        # Very short or malformed
        if features['length'] < 20:
            risk += 30
        
        # No version info
        if features['browser_version'] == 'unknown':
            risk += 20
        
        # High entropy (random)
        if features['entropy'] > 4.5:
            risk += 20
        
        return max(0, min(100, risk))
    
    def _apply_risk_rules(self, current_session: Dict) -> int:
        """Apply additional risk rules for user agents."""
        adjustment = 0
        user_agent = current_session['userAgent']
        features = extract_user_agent_features(user_agent)
        
        # Known bot patterns
        bot_keywords = ['bot', 'crawler', 'spider', 'headless', 'phantom', 'puppeteer', 'selenium']
        ua_lower = user_agent.lower()
        for keyword in bot_keywords:
            if keyword in ua_lower:
                adjustment += 30
                break
        
        # Suspicious characteristics
        if features['is_suspicious']:
            adjustment += 20
        
        # Very short or very long user agents
        if features['length'] < 20 or features['length'] > 500:
            adjustment += 15
        
        # No version information
        if features['browser_version'] == 'unknown':
            adjustment += 10
        
        # High entropy (randomized UA)
        if features['entropy'] > 4.5:
            adjustment += 15
        
        return adjustment
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save model, scaler, and threshold."""
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Save Keras model
        keras_path = save_path.replace('.pkl', '_keras.h5')
        self.model.save(keras_path)
        
        # Save other components
        components = {
            'scaler': self.scaler,
            'threshold': self.threshold,
            'version': self.version,
            'model_name': self.model_name,
        }
        joblib.dump(components, save_path)
        
        print(f"UserAgent model saved to {save_path}")
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """Load model, scaler, and threshold."""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            print(f"Model file not found: {load_path}")
            return False
        
        try:
            # Load Keras model with custom objects if needed
            keras_path = load_path.replace('.pkl', '_keras.h5')
            if os.path.exists(keras_path):
                # Try loading with compile=False first to avoid metric issues
                try:
                    self.model = tf.keras.models.load_model(keras_path, compile=False)
                    # Recompile with proper loss
                    self.model.compile(
                        optimizer='adam',
                        loss='mse',
                        metrics=['mae']
                    )
                except Exception as e:
                    print(f"Failed to load with compile=False, trying with legacy loader: {e}")
                    # Fallback to loading with custom objects
                    self.model = tf.keras.models.load_model(
                        keras_path,
                        custom_objects={'mse': tf.keras.losses.MeanSquaredError()}
                    )
                
                # Recreate encoder from the loaded model
                # Get the encoder layers (first 4 layers including input)
                encoder_input = self.model.input
                encoder_output = self.model.layers[3].output  # 4th layer is the encoded representation
                self.encoder = models.Model(encoder_input, encoder_output)
            else:
                print(f"Keras model file not found: {keras_path}")
                return False
            
            # Load other components
            components = joblib.load(load_path)
            self.scaler = components['scaler']
            self.threshold = components['threshold']
            self.version = components.get('version', 'unknown')
            
            self.is_loaded = True
            print(f"UserAgent model loaded successfully")
            return True
            
        except Exception as e:
            print(f"Error loading UserAgent model: {e}")
            # If loading fails, we can still use rule-based prediction
            self.is_loaded = False
            return False