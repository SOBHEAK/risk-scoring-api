# tests/test_integration.py
import pytest
import sys
import os
import asyncio
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from api.main import app
from config.settings import get_settings

settings = get_settings()
client = TestClient(app)

# Test API key
TEST_API_KEY = settings.api_keys[0] if settings.api_keys else "test_key"


class TestIntegrationScenarios:
    """Integration tests for complete scenarios."""
    
    def test_scenario_normal_user_workflow(self):
        """Test normal user login workflow."""
        headers = {"X-API-Key": TEST_API_KEY}
        user_id = "john.doe@company.com"
        
        # First login - new user
        now = int(datetime.now(timezone.utc).replace(hour=9).timestamp() * 1000)
        
        payload = {
            "currentSession": {
                "ip": "73.123.45.67",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "timestamp": now,
                "timezone": "America/New_York",
                "screenResolution": "1920x1080",
                "platform": "Win32",
                "isCookieEnabled": True
            },
            "loginHistory": [],
            "userId": user_id
        }
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # New user should have moderate scores
        assert 20 <= data["scores"]["overall"] <= 50
        
        # Build history
        history = [{
            "ip": "73.123.45.67",
            "userAgent": payload["currentSession"]["userAgent"],
            "timestamp": now,
            "location": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060
            },
            "loginStatus": "success"
        }]
        
        # Second login - same day, slightly different time
        now2 = now + (2 * 3600000)  # 2 hours later
        payload["currentSession"]["timestamp"] = now2
        payload["loginHistory"] = history
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # Established pattern should have lower scores
        assert data["scores"]["overall"] <= 30
    
    def test_scenario_vpn_after_normal_usage(self):
        """Test user suddenly using VPN after normal usage."""
        headers = {"X-API-Key": TEST_API_KEY}
        user_id = "vpn.test@company.com"
        
        # Build normal history
        base_time = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp() * 1000)
        history = []
        
        for i in range(10):
            history.append({
                "ip": "98.123.45.67",  # AT&T residential
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "timestamp": base_time + (i * 86400000),
                "location": {
                    "country": "United States",
                    "city": "San Francisco",
                    "latitude": 37.7749,
                    "longitude": -122.4194
                },
                "loginStatus": "success"
            })
        
        # Now login with VPN
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        payload = {
            "currentSession": {
                "ip": "104.16.123.45",  # Cloudflare/VPN
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "timestamp": now
            },
            "loginHistory": history,
            "userId": user_id
        }
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # VPN after normal usage should trigger high IP score
        assert data["scores"]["ip"] >= 70
        assert data["scores"]["overall"] >= 40
    
    def test_scenario_account_takeover_attempt(self):
        """Test typical account takeover attempt pattern."""
        headers = {"X-API-Key": TEST_API_KEY}
        user_id = "victim@company.com"
        
        # Normal user history - business hours, consistent location
        base_time = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp() * 1000)
        history = []
        
        for i in range(20):
            dt = datetime.fromtimestamp(base_time / 1000, tz=timezone.utc)
            dt = dt.replace(hour=14)  # 2 PM
            history.append({
                "ip": "71.123.45.67",  # Verizon residential
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "timestamp": int(dt.timestamp() * 1000) + (i * 86400000),
                "location": {
                    "country": "United States",
                    "city": "Boston",
                    "latitude": 42.3601,
                    "longitude": -71.0589
                },
                "loginStatus": "success"
            })
        
        # Attack attempt - different country, night time, bot UA
        attack_time = datetime.now(timezone.utc).replace(hour=3)  # 3 AM
        payload = {
            "currentSession": {
                "ip": "185.220.101.45",  # Suspicious IP
                "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
                "timestamp": int(attack_time.timestamp() * 1000)
            },
            "loginHistory": history,
            "userId": user_id
        }
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # Multiple red flags should result in very high score
        assert data["scores"]["ip"] >= 70  # Suspicious IP
        assert data["scores"]["datetime"] >= 70  # 3 AM login
        assert data["scores"]["userAgent"] >= 80  # Headless browser
        assert data["scores"]["overall"] >= 70  # High overall risk
    
    def test_scenario_credential_stuffing_attack(self):
        """Test credential stuffing attack pattern."""
        headers = {"X-API-Key": TEST_API_KEY}
        user_id = "target@company.com"
        
        # Recent burst of failed attempts
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        history = []
        
        # Add some old legitimate history
        for i in range(5):
            history.append({
                "ip": "68.123.45.67",
                "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X)",
                "timestamp": now - ((30 - i) * 86400000),
                "location": {
                    "country": "United States",
                    "city": "Miami",
                    "latitude": 25.7617,
                    "longitude": -80.1918
                },
                "loginStatus": "success"
            })
        
        # Add burst of failures (credential stuffing)
        for i in range(15):
            history.append({
                "ip": f"45.{20+i}.{30+i}.{40+i}",  # Different IPs
                "userAgent": "Mozilla/5.0",  # Simplified UA
                "timestamp": now - ((15 - i) * 60000),  # Last 15 minutes
                "location": {
                    "country": "Unknown",
                    "city": "Unknown",
                    "latitude": 0,
                    "longitude": 0
                },
                "loginStatus": "failure"
            })
        
        # Current attempt
        payload = {
            "currentSession": {
                "ip": "45.99.88.77",
                "userAgent": "Mozilla/5.0",
                "timestamp": now
            },
            "loginHistory": history,
            "userId": user_id
        }
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # Burst pattern should trigger high scores
        assert data["scores"]["datetime"] >= 60  # Burst pattern
        assert data["scores"]["overall"] >= 50
    
    def test_scenario_traveling_user(self):
        """Test legitimate traveling user."""
        headers = {"X-API-Key": TEST_API_KEY}
        user_id = "traveler@company.com"
        
        # Login from NYC
        day1 = int((datetime.now(timezone.utc) - timedelta(days=3)).timestamp() * 1000)
        
        history = [{
            "ip": "73.123.45.67",
            "userAgent": "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X)",
            "timestamp": day1,
            "location": {
                "country": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060
            },
            "loginStatus": "success"
        }]
        
        # Login from London 2 days later (reasonable travel)
        day3 = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp() * 1000)
        
        payload = {
            "currentSession": {
                "ip": "86.123.45.67",
                "userAgent": "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X)",
                "timestamp": day3
            },
            "loginHistory": history,
            "userId": user_id
        }
        
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        # Reasonable travel should not trigger extreme scores
        assert data["scores"]["geolocation"] <= 50  # New location but reasonable
        assert data["scores"]["overall"] <= 50
    
    def test_performance_concurrent_requests(self):
        """Test API performance with concurrent requests."""
        headers = {"X-API-Key": TEST_API_KEY}
        
        async def make_request(session_num):
            payload = {
                "currentSession": {
                    "ip": f"192.168.1.{session_num}",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
                },
                "loginHistory": [],
                "userId": f"user{session_num}@test.com"
            }
            
            return client.post("/api/v1/analyze", json=payload, headers=headers)
        
        # Make 10 concurrent requests
        loop = asyncio.new_event_loop()
        tasks = [loop.create_task(make_request(i)) for i in range(10)]
        responses = loop.run_until_complete(asyncio.gather(*tasks))
        
        # All should succeed
        for response in responses:
            assert response.status_code == 200
            data = response.json()
            assert data["meta"]["processingTime"] < 200  # Under 200ms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])