"""
Train UserAgent Risk Model using synthetic data
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import random
from ml_models.useragent_model import UserAgentRiskModel
from config.settings import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Legitimate user agent templates
LEGITIMATE_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    
    # Safari on iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
]

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    # Bots and crawlers
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    
    # Headless browsers
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Puppeteer",
    
    # Selenium
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Selenium",
    
    # Outdated browsers
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
    
    # Curl/Wget
    "curl/7.64.1",
    "Wget/1.20.3 (linux-gnu)",
    
    # Programming languages
    "Python-urllib/3.8",
    "Java/1.8.0_151",
    
    # Empty or minimal
    "Mozilla/5.0",
    "",
]


def generate_session_features():
    """Generate realistic browser session features"""
    # Common screen resolutions
    resolutions = [
        "1920x1080", "1366x768", "1536x864", "1440x900",
        "1280x720", "2560x1440", "3840x2160"
    ]
    
    # Common timezones
    timezones = [
        "America/New_York", "America/Chicago", "America/Los_Angeles",
        "Europe/London", "Europe/Paris", "Asia/Tokyo", "Australia/Sydney"
    ]
    
    # Common platforms
    platforms = ["Win32", "MacIntel", "Linux x86_64", "iPhone", "Android"]
    
    # Common plugins (getting rare)
    plugins = [
        [], 
        ["Chrome PDF Plugin", "Chrome PDF Viewer"],
        ["Shockwave Flash"]
    ]
    
    features = {
        'screenResolution': random.choice(resolutions),
        'timezone': random.choice(timezones),
        'platform': random.choice(platforms),
        'hardwareConcurrency': random.choice([2, 4, 8, 16]),
        'deviceMemory': random.choice([2, 4, 8, 16, 32]),
        'touchSupport': random.random() < 0.3,  # 30% mobile
        'isCookieEnabled': True,
        'isJavaEnabled': False,
        'plugins': random.choice(plugins),
        'canvasFingerprint': f"canvas_{random.randint(1000000, 9999999)}",
        'webglRenderer': "ANGLE (Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0)"
    }
    
    return features


def generate_training_data(num_samples=10000):
    """Generate synthetic training data for legitimate users"""
    training_data = []
    
    for i in range(num_samples):
        # Pick a legitimate user agent
        user_agent = random.choice(LEGITIMATE_USER_AGENTS)
        
        # Generate consistent session features
        session_features = generate_session_features()
        
        # Make features consistent with user agent
        if "iPhone" in user_agent or "Android" in user_agent:
            session_features['touchSupport'] = True
            session_features['plugins'] = []
            if "iPhone" in user_agent:
                session_features['platform'] = "iPhone"
            else:
                session_features['platform'] = "Android"
        elif "Windows" in user_agent:
            session_features['platform'] = "Win32"
            session_features['touchSupport'] = False
        elif "Mac" in user_agent:
            session_features['platform'] = "MacIntel"
            session_features['touchSupport'] = False
        
        session_data = {
            'userAgent': user_agent,
            'currentSession': session_features
        }
        
        training_data.append(session_data)
    
    return training_data


def generate_anomaly_data(num_samples=500):
    """Generate synthetic anomaly data"""
    anomaly_data = []
    
    for i in range(num_samples):
        anomaly_type = random.choice(['bot', 'headless', 'outdated', 'inconsistent', 'empty'])
        
        if anomaly_type in ['bot', 'headless', 'outdated', 'empty']:
            user_agent = random.choice(SUSPICIOUS_USER_AGENTS)
            session_features = generate_session_features()
            
            # Bots often have minimal features
            if anomaly_type == 'bot':
                session_features['plugins'] = []
                session_features['canvasFingerprint'] = None
                session_features['hardwareConcurrency'] = 1
                
        elif anomaly_type == 'inconsistent':
            # Inconsistent UA and features
            user_agent = random.choice(LEGITIMATE_USER_AGENTS)
            session_features = generate_session_features()
            
            # Create inconsistencies
            if "Windows" in user_agent:
                session_features['platform'] = "MacIntel"  # Wrong platform
            if "iPhone" in user_agent:
                session_features['touchSupport'] = False  # Should have touch
                session_features['plugins'] = ["Flash"]   # iPhones don't have plugins
            
        session_data = {
            'userAgent': user_agent,
            'currentSession': session_features
        }
        
        anomaly_data.append(session_data)
    
    return anomaly_data


def main():
    """Train the UserAgent Risk Model"""
    logger.info("Generating training data...")
    
    # Generate legitimate data
    legitimate_data = generate_training_data(10000)
    logger.info(f"Generated {len(legitimate_data)} legitimate samples")
    
    # Initialize and train model
    model = UserAgentRiskModel(f"{settings.MODELS_PATH}/useragent_model.pkl")
    
    logger.info("Training UserAgent Risk Model...")
    model.train(legitimate_data)
    
    # Save model
    os.makedirs(settings.MODELS_PATH, exist_ok=True)
    model.save_model()
    logger.info(f"Model saved to {settings.MODELS_PATH}/useragent_model.pkl")
    
    # Test on anomalies
    logger.info("Testing on anomaly data...")
    anomaly_data = generate_anomaly_data(100)
    
    legitimate_scores = []
    anomaly_scores = []
    
    # Test legitimate samples
    for data in legitimate_data[:100]:
        score = model.predict_risk(data['currentSession'])
        legitimate_scores.append(score)
    
    # Test anomaly samples
    for data in anomaly_data:
        score = model.predict_risk(data['currentSession'])
        anomaly_scores.append(score)
    
    logger.info(f"Legitimate scores - Mean: {np.mean(legitimate_scores):.2f}, "
                f"Std: {np.std(legitimate_scores):.2f}")
    logger.info(f"Anomaly scores - Mean: {np.mean(anomaly_scores):.2f}, "
                f"Std: {np.std(anomaly_scores):.2f}")
    
    # Test specific cases
    test_cases = [
        {
            'name': 'Puppeteer',
            'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Puppeteer',
            'currentSession': {'plugins': [], 'hardwareConcurrency': 1}
        },
        {
            'name': 'Curl',
            'userAgent': 'curl/7.64.1',
            'currentSession': {}
        },
        {
            'name': 'Normal Chrome',
            'userAgent': LEGITIMATE_USER_AGENTS[0],
            'currentSession': generate_session_features()
        }
    ]
    
    logger.info("\nSpecific test cases:")
    for test in test_cases:
        score = model.predict_risk(test)
        logger.info(f"{test['name']}: Risk score = {score}")


if __name__ == "__main__":
    main()