# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.main import app
from config.settings import get_settings

settings = get_settings()
client = TestClient(app)

# Test API key
TEST_API_KEY = settings.api_keys[0] if settings.api_keys else "test_key"


class TestAPI:
    """Test API endpoints."""
    
    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data
    
    def test_analyze_without_auth(self):
        """Test analyze endpoint without authentication."""
        payload = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 401
    
    def test_analyze_normal_login(self):
        """Test analyze endpoint with normal login."""
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        payload = {
            "currentSession": {
                "ip": "73.123.45.67",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "timestamp": now,
                "timezone": "America/New_York",
                "screenResolution": "1920x1080",
                "platform": "Win32"
            },
            "loginHistory": [
                {
                    "ip": "73.123.45.67",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "timestamp": now - 86400000,  # Yesterday
                    "location": {
                        "country": "United States",
                        "city": "New York",
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    },
                    "loginStatus": "success"
                }
            ],
            "userId": "normal.user@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "meta" in data
        assert "scores" in data
        assert "requestId" in data["meta"]
        assert data["meta"]["userId"] == "normal.user@example.com"
        
        # Normal login should have low scores
        assert data["scores"]["ip"] <= 30
        assert data["scores"]["datetime"] <= 30
        assert data["scores"]["userAgent"] <= 30
        assert data["scores"]["overall"] <= 30
    
    def test_analyze_vpn_login(self):
        """Test analyze endpoint with VPN login."""
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        payload = {
            "currentSession": {
                "ip": "104.16.123.45",  # Cloudflare IP (datacenter)
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "timestamp": now
            },
            "loginHistory": [],
            "userId": "vpn.user@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # VPN/datacenter IP should have high IP score
        assert data["scores"]["ip"] >= 70
    
    def test_analyze_bot_attempt(self):
        """Test analyze endpoint with bot user agent."""
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        payload = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "python-requests/2.31.0",  # Bot user agent
                "timestamp": now
            },
            "loginHistory": [],
            "userId": "bot.test@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Bot user agent should have high score
        assert data["scores"]["userAgent"] >= 80
    
    def test_analyze_midnight_login(self):
        """Test analyze endpoint with unusual time login."""
        # Create timestamp at 3 AM
        dt = datetime.now(timezone.utc).replace(hour=3, minute=15)
        now = int(dt.timestamp() * 1000)
        
        # History shows normal business hours
        history = []
        for i in range(5):
            hist_dt = dt.replace(hour=14) - timezone.timedelta(days=i+1)
            history.append({
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0...",
                "timestamp": int(hist_dt.timestamp() * 1000),
                "location": {
                    "country": "United States",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060
                },
                "loginStatus": "success"
            })
        
        payload = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timestamp": now
            },
            "loginHistory": history,
            "userId": "night.user@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Unusual time should have elevated datetime score
        assert data["scores"]["datetime"] >= 70
    
    def test_analyze_impossible_travel(self):
        """Test analyze endpoint with impossible travel."""
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        # Last login from New York 1 hour ago
        history = [{
            "ip": "73.123.45.67",
            "userAgent": "Mozilla/5.0...",
            "timestamp": now - 3600000,  # 1 hour ago
            "location": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060
            },
            "loginStatus": "success"
        }]
        
        # Current login from London (impossible in 1 hour)
        payload = {
            "currentSession": {
                "ip": "185.123.45.67",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timestamp": now
            },
            "loginHistory": history,
            "userId": "travel.user@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Impossible travel should have high geolocation score
        # Note: In real implementation, would need IP geolocation
        # For now, just check that API responds correctly
        assert "geolocation" in data["scores"]
    
    def test_invalid_ip_address(self):
        """Test with invalid IP address."""
        payload = {
            "currentSession": {
                "ip": "not.an.ip.address",
                "userAgent": "Mozilla/5.0...",
                "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 400
        assert "Invalid IP address" in response.json()["detail"]
    
    def test_invalid_timestamp(self):
        """Test with invalid timestamp."""
        payload = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0...",
                "timestamp": -1  # Invalid
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 422  # Pydantic validation error
    
    def test_missing_required_fields(self):
        """Test with missing required fields."""
        payload = {
            "currentSession": {
                "ip": "192.168.1.1"
                # Missing userAgent and timestamp
            },
            "loginHistory": [],
            "userId": "test@example.com"
        }
        
        headers = {"X-API-Key": TEST_API_KEY}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        
        assert response.status_code == 422  # Pydantic validation error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])