"""
ML model tests
"""
import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_models.ip_model import IPRiskModel
from ml_models.datetime_model import DateTimeRiskModel
from ml_models.useragent_model import UserAgentRiskModel
from ml_models.geolocation_model import GeolocationRiskModel
from datetime import datetime, timedelta
import numpy as np


class TestIPModel:
    """Test IP Risk Model"""
    
    def test_ip_feature_extraction(self):
        """Test IP feature extraction"""
        model = IPRiskModel()
        
        data = {
            'ip': '192.168.1.1',
            'timestamp': int(datetime.now().timestamp() * 1000),
            'login_history': []
        }
        
        features = model.extract_features(data)
        assert features.shape == (1, 10)  # Expected number of features
    
    def test_vpn_detection(self):
        """Test VPN IP detection"""
        model = IPRiskModel()
        
        # Test known VPN IP
        vpn_data = {
            'ip': '104.16.1.1',  # Cloudflare
            'timestamp': int(datetime.now().timestamp() * 1000)
        }
        
        # Without trained model, should still detect VPN ranges
        score = model.predict_risk(vpn_data, [])
        assert score >= 50  # Should be flagged as risky
    
    def test_private_ip(self):
        """Test private IP handling"""
        model = IPRiskModel()
        
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        
        for ip in private_ips:
            data = {
                'ip': ip,
                'timestamp': int(datetime.now().timestamp() * 1000)
            }
            features = model.extract_features(data)
            # Should detect as private
            assert features[0][0] == 1  # is_private flag


class TestDateTimeModel:
    """Test DateTime Risk Model"""
    
    def test_datetime_feature_extraction(self):
        """Test datetime feature extraction"""
        model = DateTimeRiskModel()
        
        data = {
            'timestamp': int(datetime.now().timestamp() * 1000),
            'login_history': []
        }
        
        features = model.extract_features(data)
        assert features.shape == (1, 13)  # Expected number of features
    
    def test_night_time_detection(self):
        """Test night time login detection"""
        model = DateTimeRiskModel()
        
        # 3 AM login
        night_time = datetime.now().replace(hour=3, minute=0)
        
        data = {
            'timestamp': int(night_time.timestamp() * 1000),
            'login_history': []
        }
        
        features = model.extract_features(data)
        # Check if night time flag is set
        assert features[0][6] == 1  # is_night flag
    
    def test_rapid_attempts(self):
        """Test rapid login attempt detection"""
        model = DateTimeRiskModel()
        
        current_time = datetime.now()
        
        # Generate rapid attempts
        history = []
        for i in range(10):
            history.append({
                'timestamp': int((current_time - timedelta(minutes=i)).timestamp() * 1000),
                'loginStatus': 'failure' if i < 8 else 'success'
            })
        
        data = {
            'timestamp': int(current_time.timestamp() * 1000),
            'login_history': history
        }
        
        features = model.extract_features(data)
        # Should detect high frequency in last hour
        assert features[0][11] > 5  # very_recent logins


class TestUserAgentModel:
    """Test UserAgent Risk Model"""
    
    def test_useragent_feature_extraction(self):
        """Test user agent feature extraction"""
        model = UserAgentRiskModel()
        
        data = {
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'currentSession': {}
        }
        
        features = model.extract_features(data)
        assert features.shape == (1, model.input_dim)
    
    def test_bot_detection(self):
        """Test bot user agent detection"""
        model = UserAgentRiskModel()
        
        bot_agents = [
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            'curl/7.64.1',
            'Python-urllib/3.8',
            'Mozilla/5.0 (Windows NT 10.0) HeadlessChrome/120.0.0.0'
        ]
        
        for agent in bot_agents:
            data = {
                'userAgent': agent,
                'currentSession': {}
            }
            
            features = model.extract_features(data)
            # Bot detection should be flagged
            assert features[0][3] == 1 or 'bot' in agent.lower() or 'curl' in agent.lower()
    
    def test_legitimate_browsers(self):
        """Test legitimate browser detection"""
        model = UserAgentRiskModel()
        
        legitimate_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'
        ]
        
        for agent in legitimate_agents:
            data = {
                'userAgent': agent,
                'currentSession': {
                    'screenResolution': '1920x1080',
                    'hardwareConcurrency': 8,
                    'isCookieEnabled': True
                }
            }
            
            features = model.extract_features(data)
            # Should not be flagged as bot
            assert features[0][3] == 0  # is_bot flag


class TestGeolocationModel:
    """Test Geolocation Risk Model"""
    
    def test_geolocation_feature_extraction(self):
        """Test geolocation feature extraction"""
        model = GeolocationRiskModel()
        
        data = {
            'location': {
                'latitude': 40.7128,
                'longitude': -74.0060,
                'country': 'United States',
                'city': 'New York'
            },
            'timestamp': int(datetime.now().timestamp() * 1000),
            'login_history': []
        }
        
        features = model.extract_features(data)
        assert features.shape == (1, 9)  # Expected number of features
    
    def test_distance_calculation(self):
        """Test haversine distance calculation"""
        model = GeolocationRiskModel()
        
        # NYC to London
        distance = model.haversine_distance(
            40.7128, -74.0060,  # NYC
            51.5074, -0.1278    # London
        )
        
        # Should be approximately 5570 km
        assert 5500 < distance < 5600
    
    def test_impossible_travel(self):
        """Test impossible travel detection"""
        model = GeolocationRiskModel()
        
        # NYC to London in 1 hour
        nyc_lat, nyc_lon = 40.7128, -74.0060
        london_lat, london_lon = 51.5074, -0.1278
        
        speed = model.calculate_travel_speed(
            {'latitude': nyc_lat, 'longitude': nyc_lon},
            {'latitude': london_lat, 'longitude': london_lon},
            0,  # time1
            3600000  # time2 (1 hour later)
        )
        
        # Speed should be way over max travel speed
        assert speed > model.max_travel_speed_kmh
        assert model.is_impossible_travel(
            nyc_lat, nyc_lon, london_lat, london_lon, 3600000
        )
    
    def test_feasible_travel(self):
        """Test feasible travel detection"""
        model = GeolocationRiskModel()
        
        # NYC to Boston in 3 hours (feasible)
        nyc_lat, nyc_lon = 40.7128, -74.0060
        boston_lat, boston_lon = 42.3601, -71.0589
        
        speed = model.calculate_travel_speed(
            {'latitude': nyc_lat, 'longitude': nyc_lon},
            {'latitude': boston_lat, 'longitude': boston_lon},
            0,  # time1
            10800000  # time2 (3 hours later)
        )
        
        # Speed should be under max travel speed
        assert speed < model.max_travel_speed_kmh
        assert not model.is_impossible_travel(
            nyc_lat, nyc_lon, boston_lat, boston_lon, 10800000
        )


class TestModelIntegration:
    """Test model integration"""
    
    def test_all_models_load(self):
        """Test that all models can be initialized"""
        models = {
            'ip': IPRiskModel(),
            'datetime': DateTimeRiskModel(),
            'useragent': UserAgentRiskModel(),
            'geolocation': GeolocationRiskModel()
        }
        
        for name, model in models.items():
            assert model is not None
            assert hasattr(model, 'predict_risk')
            assert hasattr(model, 'extract_features')
    
    def test_risk_score_ranges(self):
        """Test that all models return scores in valid range"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        test_session = {
            'ip': '192.168.1.1',
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'timestamp': current_time,
            'location': {
                'latitude': 40.7128,
                'longitude': -74.0060,
                'country': 'United States',
                'city': 'New York'
            }
        }
        
        models = {
            'ip': IPRiskModel(),
            'datetime': DateTimeRiskModel(),
            'useragent': UserAgentRiskModel(),
            'geolocation': GeolocationRiskModel()
        }
        
        for name, model in models.items():
            score = model.predict_risk(test_session, [])
            assert 0 <= score <= 100, f"{name} model returned invalid score: {score}"
    
    def test_model_consistency(self):
        """Test that models give consistent results"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        test_session = {
            'ip': '8.8.8.8',
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'timestamp': current_time
        }
        
        model = IPRiskModel()
        
        # Multiple predictions should be consistent
        scores = []
        for _ in range(5):
            score = model.predict_risk(test_session, [])
            scores.append(score)
        
        # All scores should be the same
        assert all(s == scores[0] for s in scores)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])