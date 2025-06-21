"""
API endpoint tests
"""
import pytest
from fastapi.testclient import TestClient
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.main import app
from datetime import datetime, timedelta

client = TestClient(app)

# Test API key
TEST_API_KEY = "xayone-test-key-123"


class TestAPIEndpoints:
    """Test API endpoints"""
    
    def test_root_endpoint(self):
        """Test root endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
    
    def test_analyze_without_auth(self):
        """Test analyze endpoint without authentication"""
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post("/api/v1/analyze", json=test_data)
        assert response.status_code == 401
    
    def test_analyze_with_auth(self):
        """Test analyze endpoint with authentication"""
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "meta" in data
        assert "scores" in data
        
        # Check meta fields
        assert "requestId" in data["meta"]
        assert "userId" in data["meta"]
        assert "timestamp" in data["meta"]
        assert "processingTime" in data["meta"]
        assert "modelsVersion" in data["meta"]
        
        # Check scores
        assert "ip" in data["scores"]
        assert "datetime" in data["scores"]
        assert "userAgent" in data["scores"]
        assert "geolocation" in data["scores"]
        assert "overall" in data["scores"]
        
        # Check score ranges
        for score_type, score_value in data["scores"].items():
            assert 0 <= score_value <= 100
    
    def test_analyze_invalid_ip(self):
        """Test analyze with invalid IP"""
        test_data = {
            "currentSession": {
                "ip": "invalid-ip",
                "userAgent": "Mozilla/5.0",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 400
    
    def test_analyze_invalid_timestamp(self):
        """Test analyze with invalid timestamp"""
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0",
                "timestamp": -1  # Invalid
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 400
    
    def test_analyze_with_history(self):
        """Test analyze with login history"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": current_time
            },
            "loginHistory": [
                {
                    "ip": "192.168.1.1",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                    "timestamp": current_time - 3600000,  # 1 hour ago
                    "location": {
                        "country": "United States",
                        "city": "New York",
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    },
                    "loginStatus": "success"
                }
            ],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["scores"]["overall"] >= 0


class TestRiskScenarios:
    """Test specific risk scenarios"""
    
    def test_vpn_detection(self):
        """Test VPN IP detection"""
        test_data = {
            "currentSession": {
                "ip": "104.16.1.1",  # Cloudflare IP
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 200
        
        data = response.json()
        # VPN IPs should have higher risk
        assert data["scores"]["ip"] >= 50
    
    def test_bot_detection(self):
        """Test bot user agent detection"""
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 200
        
        data = response.json()
        # Bot user agents should have high risk
        assert data["scores"]["userAgent"] >= 70
    
    def test_unusual_time_detection(self):
        """Test unusual login time detection"""
        # 3 AM login
        dt = datetime.now().replace(hour=3, minute=0)
        
        test_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": int(dt.timestamp() * 1000)
            },
            "loginHistory": [
                {
                    "ip": "192.168.1.1",
                    "userAgent": "Mozilla/5.0",
                    "timestamp": int((dt - timedelta(days=1)).replace(hour=14).timestamp() * 1000),
                    "location": {
                        "country": "United States",
                        "city": "New York",
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    },
                    "loginStatus": "success"
                }
                for dt in [datetime.now() - timedelta(days=i) for i in range(1, 10)]
            ],
            "userId": "test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=test_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        assert response.status_code == 200
        
        data = response.json()
        # Unusual time should increase datetime risk
        assert data["scores"]["datetime"] >= 30


if __name__ == "__main__":
    pytest.main([__file__, "-v"])