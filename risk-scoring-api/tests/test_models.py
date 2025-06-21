# tests/test_models.py
import pytest
import sys
import os
from datetime import datetime, timezone

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_models.ip_model import IPRiskModel
from ml_models.datetime_model import DateTimeRiskModel
from ml_models.useragent_model import UserAgentRiskModel
from ml_models.geolocation_model import GeolocationRiskModel


class TestIPModel:
    """Test IP risk model."""
    
    def test_ip_feature_extraction(self):
        """Test IP feature extraction."""
        model = IPRiskModel()
        
        current_session = {'ip': '192.168.1.1'}
        history = [
            {'ip': '192.168.1.1'},
            {'ip': '192.168.1.2'}
        ]
        
        features = model.extract_features(current_session, history)
        
        assert len(features) == 10  # Check feature vector length
        assert features[0] == 0  # is_new_ip (seen before)
        assert features[3] == 1  # is_private
    
    def test_datacenter_ip_detection(self):
        """Test datacenter IP detection."""
        model = IPRiskModel()
        
        # Cloudflare IP
        current_session = {'ip': '104.16.123.45'}
        features = model.extract_features(current_session, [])
        
        assert features[1] == 1  # is_datacenter
        assert features[4] == 1  # is_suspicious_type


class TestDateTimeModel:
    """Test datetime risk model."""
    
    def test_datetime_feature_extraction(self):
        """Test datetime feature extraction."""
        model = DateTimeRiskModel()
        
        now = datetime.now(timezone.utc).replace(hour=14)  # 2 PM
        current_session = {'timestamp': int(now.timestamp() * 1000)}
        history = []
        
        features = model.extract_features(current_session, history)
        
        assert len(features) == 10  # Check feature vector length
        assert features[3] == 1  # is_business_hours
        assert features[4] == 0  # is_night
    
    def test_burst_pattern_detection(self):
        """Test burst pattern detection."""
        model = DateTimeRiskModel()
        
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        current_session = {'timestamp': now}
        
        # Create burst pattern in history
        history = []
        for i in range(10):
            history.append({
                'timestamp': now - (i * 60 * 1000)  # Every minute
            })
        
        features = model.extract_features(current_session, history)
        assert features[7] == 1  # is_burst_pattern


class TestUserAgentModel:
    """Test user agent risk model."""
    
    def test_bot_detection(self):
        """Test bot user agent detection."""
        model = UserAgentRiskModel()
        
        # Bot user agent
        bot_session = {'userAgent': 'python-requests/2.31.0'}
        features = model.extract_features(bot_session, [])
        
        assert features[1] == 1  # is_bot
        assert features[14] == 1  # is_suspicious
    
    def test_normal_browser(self):
        """Test normal browser detection."""
        model = UserAgentRiskModel()
        
        # Normal Chrome
        normal_session = {
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        features = model.extract_features(normal_session, [])
        
        assert features[1] == 0  # is_bot
        assert features[14] == 0  # is_suspicious
        assert features[4] == 1  # is_pc


class TestGeolocationModel:
    """Test geolocation risk model."""
    
    def test_location_feature_extraction(self):
        """Test location feature extraction."""
        model = GeolocationRiskModel()
        
        current_session = {
            'ip': '73.123.45.67',
            'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000)
        }
        
        history = [{
            'ip': '73.123.45.67',
            'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000) - 86400000,
            'location': {
                'country': 'United States',
                'city': 'New York',
                'latitude': 40.7128,
                'longitude': -74.0060
            }
        }]
        
        features = model.extract_features(current_session, history)
        assert len(features) == 8  # Check feature vector length
    
    def test_impossible_travel_detection(self):
        """Test impossible travel detection."""
        model = GeolocationRiskModel()
        
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # NYC location 1 hour ago
        nyc_location = {
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        }
        
        # London location now
        london_location = {
            'country': 'United Kingdom',
            'city': 'London',
            'latitude': 51.5074,
            'longitude': -0.1278
        }
        
        # Check impossible travel
        is_impossible = model._check_impossible_travel(
            now,
            london_location,
            [{
                'timestamp': now - 3600000,  # 1 hour ago
                'location': nyc_location
            }]
        )
        
        assert is_impossible == True


class TestModelIntegration:
    """Test model integration."""
    
    def test_all_models_load(self):
        """Test that all models can be instantiated."""
        models = {
            'ip': IPRiskModel(),
            'datetime': DateTimeRiskModel(),
            'useragent': UserAgentRiskModel(),
            'geolocation': GeolocationRiskModel()
        }
        
        for name, model in models.items():
            assert model is not None
            assert model.model_name is not None
            assert model.version == "v1.0.0"
    
    def test_model_predictions_in_range(self):
        """Test that model predictions are in valid range."""
        models = {
            'ip': IPRiskModel(),
            'datetime': DateTimeRiskModel(),
            'useragent': UserAgentRiskModel(),
            'geolocation': GeolocationRiskModel()
        }
        
        # Test session
        current_session = {
            'ip': '192.168.1.1',
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000)
        }
        
        history = []
        
        for name, model in models.items():
            # Models might not be trained, so check if they handle it gracefully
            try:
                if model.is_loaded or name == 'geolocation':  # Geolocation has fallback
                    score = model.predict(current_session, history)
                    assert 0 <= score <= 100, f"{name} model score out of range: {score}"
            except RuntimeError as e:
                # Expected if model not loaded
                assert "not loaded" in str(e)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])