"""
Integration tests for the complete system
"""
import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from api.main import app
from datetime import datetime, timedelta
import time

client = TestClient(app)
TEST_API_KEY = "xayone-test-key-123"


class TestIntegrationScenarios:
    """Test complete user scenarios"""
    
    def test_normal_user_flow(self):
        """Test normal user login flow - should get low risk scores"""
        # User's typical login pattern
        current_time = int(datetime.now().replace(hour=14).timestamp() * 1000)
        
        # Build consistent login history
        login_history = []
        for i in range(10):
            past_time = current_time - (i * 86400000)  # Days ago
            login_history.append({
                "ip": "73.45.123.45",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": past_time,
                "location": {
                    "country": "United States",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060
                },
                "loginStatus": "success"
            })
        
        request_data = {
            "currentSession": {
                "ip": "73.45.123.45",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": current_time,
                "screenResolution": "1920x1080",
                "timezone": "America/New_York",
                "platform": "Win32",
                "hardwareConcurrency": 8,
                "touchSupport": False,
                "isCookieEnabled": True
            },
            "loginHistory": login_history,
            "userId": "normal.user@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=request_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Normal user should have low risk scores
        assert data["scores"]["overall"] <= 30
        assert data["scores"]["ip"] <= 30
        assert data["scores"]["datetime"] <= 30
        assert data["scores"]["userAgent"] <= 30
        assert data["scores"]["geolocation"] <= 30
    
    def test_vpn_with_new_device(self):
        """Test VPN + new device - should get high risk scores"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        # Normal history
        login_history = []
        for i in range(5):
            past_time = current_time - (i * 86400000)
            login_history.append({
                "ip": "73.45.123.45",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0",
                "timestamp": past_time,
                "location": {
                    "country": "United States",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060
                },
                "loginStatus": "success"
            })
        
        # Current session from VPN with new browser
        request_data = {
            "currentSession": {
                "ip": "104.16.1.1",  # Cloudflare VPN
                "userAgent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0",  # Different OS/Browser
                "timestamp": current_time
            },
            "loginHistory": login_history,
            "userId": "vpn.user@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=request_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # VPN + new device should trigger high risk
        assert data["scores"]["overall"] >= 50
        assert data["scores"]["ip"] >= 70  # VPN detected
    
    def test_impossible_travel(self):
        """Test impossible travel scenario"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        # Login from NYC 1 hour ago
        login_history = [{
            "ip": "73.45.123.45",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "timestamp": current_time - 3600000,  # 1 hour ago
            "location": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060
            },
            "loginStatus": "success"
        }]
        
        # Current login from London (impossible in 1 hour)
        request_data = {
            "currentSession": {
                "ip": "81.2.69.142",  # UK IP
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": current_time
            },
            "loginHistory": login_history,
            "userId": "traveler@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=request_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Impossible travel should trigger very high geolocation risk
        assert data["scores"]["geolocation"] >= 85
        assert data["scores"]["overall"] >= 50
    
    def test_bot_attempt(self):
        """Test bot/automated tool detection"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        request_data = {
            "currentSession": {
                "ip": "45.142.182.31",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Headless",
                "timestamp": current_time,
                "plugins": [],  # Bots typically have no plugins
                "hardwareConcurrency": 1,  # Low core count
                "touchSupport": False
            },
            "loginHistory": [],
            "userId": "bot.test@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=request_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Headless browser should be detected
        assert data["scores"]["userAgent"] >= 80
        assert data["scores"]["overall"] >= 50
    
    def test_brute_force_pattern(self):
        """Test brute force attack pattern"""
        current_time = int(datetime.now().timestamp() * 1000)
        
        # Many failed attempts in short time
        login_history = []
        for i in range(10):
            login_history.append({
                "ip": "45.142.182.31",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": current_time - (i * 60000),  # Every minute
                "location": {
                    "country": "Russia",
                    "city": "Moscow",
                    "latitude": 55.7558,
                    "longitude": 37.6173
                },
                "loginStatus": "failure"
            })
        
        request_data = {
            "currentSession": {
                "ip": "45.142.182.31",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": current_time
            },
            "loginHistory": login_history,
            "userId": "target@example.com"
        }
        
        response = client.post(
            "/api/v1/analyze",
            json=request_data,
            headers={"X-API-Key": TEST_API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Rapid failed attempts should trigger high datetime risk
        assert data["scores"]["datetime"] >= 50
        assert data["scores"]["overall"] >= 40
    
    def test_performance_benchmark(self):
        """Test API performance under load"""
        request_data = {
            "currentSession": {
                "ip": "192.168.1.1",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "timestamp": int(datetime.now().timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": "perf.test@example.com"
        }
        
        # Measure response times
        response_times = []
        
        for _ in range(10):
            start_time = time.time()
            
            response = client.post(
                "/api/v1/analyze",
                json=request_data,
                headers={"X-API-Key": TEST_API_KEY}
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            response_times.append(response_time)
            
            assert response.status_code == 200
        
        # Check average response time
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 200  # Should be under 200ms
        
        # Check consistency
        data = response.json()
        assert data["meta"]["processingTime"] < 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])