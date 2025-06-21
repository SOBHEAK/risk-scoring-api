#!/usr/bin/env python3
"""
Test script to verify the Risk Scoring API is working correctly.
Run this after deployment to ensure everything is functioning.
"""

import requests
import json
from datetime import datetime, timezone
from time import time

# Configuration
API_URL = "http://localhost:8000"
API_KEY = "xayone_test_key_123"  # Update with your API key

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def print_result(test_name: str, passed: bool, details: str = ""):
    """Print test result with color."""
    status = f"{GREEN}PASSED{RESET}" if passed else f"{RED}FAILED{RESET}"
    print(f"{test_name}: {status}")
    if details:
        print(f"  {details}")


def test_health_check():
    """Test health check endpoint."""
    print(f"\n{BLUE}Testing Health Check...{RESET}")
    
    try:
        response = requests.get(f"{API_URL}/health")
        data = response.json()
        
        passed = (
            response.status_code == 200 and
            data.get("status") == "healthy"
        )
        
        details = f"Models: {data.get('models_loaded')}, " \
                 f"DB: {data.get('database_connected')}, " \
                 f"Redis: {data.get('redis_connected')}"
        
        print_result("Health Check", passed, details)
        return passed
    except Exception as e:
        print_result("Health Check", False, str(e))
        return False


def test_normal_login():
    """Test normal login scenario."""
    print(f"\n{BLUE}Testing Normal Login...{RESET}")
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "currentSession": {
            "ip": "73.123.45.67",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
            "timezone": "America/New_York",
            "platform": "Win32"
        },
        "loginHistory": [],
        "userId": "normal.user@test.com"
    }
    
    try:
        start_time = time()
        response = requests.post(
            f"{API_URL}/api/v1/analyze",
            headers=headers,
            json=payload
        )
        response_time = int((time() - start_time) * 1000)
        
        data = response.json()
        
        if response.status_code == 200:
            scores = data.get("scores", {})
            overall = scores.get("overall", 100)
            
            passed = overall <= 30  # Should be low risk
            details = f"Overall score: {overall}, Response time: {response_time}ms"
            
            print_result("Normal Login", passed, details)
            print(f"  Scores: IP={scores.get('ip')}, DateTime={scores.get('datetime')}, "
                  f"UserAgent={scores.get('userAgent')}, Geo={scores.get('geolocation')}")
            return passed
        else:
            print_result("Normal Login", False, f"Status: {response.status_code}")
            return False
            
    except Exception as e:
        print_result("Normal Login", False, str(e))
        return False


def test_vpn_detection():
    """Test VPN/datacenter IP detection."""
    print(f"\n{BLUE}Testing VPN Detection...{RESET}")
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "currentSession": {
            "ip": "104.16.123.45",  # Cloudflare IP
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
        },
        "loginHistory": [],
        "userId": "vpn.user@test.com"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/analyze",
            headers=headers,
            json=payload
        )
        
        data = response.json()
        
        if response.status_code == 200:
            ip_score = data.get("scores", {}).get("ip", 0)
            passed = ip_score >= 70  # Should detect as high risk
            
            print_result("VPN Detection", passed, f"IP score: {ip_score}")
            return passed
        else:
            print_result("VPN Detection", False, f"Status: {response.status_code}")
            return False
            
    except Exception as e:
        print_result("VPN Detection", False, str(e))
        return False


def test_bot_detection():
    """Test bot user agent detection."""
    print(f"\n{BLUE}Testing Bot Detection...{RESET}")
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "currentSession": {
            "ip": "192.168.1.1",
            "userAgent": "python-requests/2.31.0",  # Bot UA
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
        },
        "loginHistory": [],
        "userId": "bot.test@test.com"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/analyze",
            headers=headers,
            json=payload
        )
        
        data = response.json()
        
        if response.status_code == 200:
            ua_score = data.get("scores", {}).get("userAgent", 0)
            passed = ua_score >= 80  # Should detect as bot
            
            print_result("Bot Detection", passed, f"UserAgent score: {ua_score}")
            return passed
        else:
            print_result("Bot Detection", False, f"Status: {response.status_code}")
            return False
            
    except Exception as e:
        print_result("Bot Detection", False, str(e))
        return False


def test_unusual_time():
    """Test unusual login time detection."""
    print(f"\n{BLUE}Testing Unusual Time Detection...{RESET}")
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    # Create timestamp at 3 AM
    dt = datetime.now(timezone.utc).replace(hour=3, minute=15)
    
    payload = {
        "currentSession": {
            "ip": "192.168.1.1",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": int(dt.timestamp() * 1000)
        },
        "loginHistory": [],
        "userId": "night.user@test.com"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/analyze",
            headers=headers,
            json=payload
        )
        
        data = response.json()
        
        if response.status_code == 200:
            time_score = data.get("scores", {}).get("datetime", 0)
            passed = time_score >= 70  # Should detect as unusual
            
            print_result("Unusual Time Detection", passed, f"DateTime score: {time_score}")
            return passed
        else:
            print_result("Unusual Time Detection", False, f"Status: {response.status_code}")
            return False
            
    except Exception as e:
        print_result("Unusual Time Detection", False, str(e))
        return False


def test_performance():
    """Test API performance."""
    print(f"\n{BLUE}Testing Performance...{RESET}")
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    response_times = []
    
    for i in range(10):
        payload = {
            "currentSession": {
                "ip": f"192.168.1.{i+1}",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)
            },
            "loginHistory": [],
            "userId": f"perf.test{i}@test.com"
        }
        
        try:
            start_time = time()
            response = requests.post(
                f"{API_URL}/api/v1/analyze",
                headers=headers,
                json=payload
            )
            response_time = (time() - start_time) * 1000
            
            if response.status_code == 200:
                response_times.append(response_time)
        except:
            pass
    
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        passed = avg_time < 200  # Should be under 200ms
        
        print_result(
            "Performance", 
            passed, 
            f"Avg: {avg_time:.0f}ms, Max: {max_time:.0f}ms, Requests: {len(response_times)}/10"
        )
        return passed
    else:
        print_result("Performance", False, "No successful requests")
        return False


def main():
    """Run all tests."""
    print(f"{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}Xayone Risk Scoring API - Deployment Test{RESET}")
    print(f"{YELLOW}{'='*60}{RESET}")
    
    tests = [
        test_health_check,
        test_normal_login,
        test_vpn_detection,
        test_bot_detection,
        test_unusual_time,
        test_performance
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}Test Summary: {passed}/{total} passed{RESET}")
    
    if passed == total:
        print(f"{GREEN}All tests passed! API is working correctly.{RESET}")
    else:
        print(f"{RED}Some tests failed. Please check the API logs.{RESET}")
    
    print(f"{YELLOW}{'='*60}{RESET}")


if __name__ == "__main__":
    main()