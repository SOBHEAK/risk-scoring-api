# training/train_useragent_model.py
import random
from typing import Dict, List
from ml_models.useragent_model import UserAgentRiskModel


def generate_useragent_training_data() -> Dict[str, List]:
    """Generate synthetic training data for user agent model."""
    
    # Normal user agents (real browsers)
    normal_agents = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        
        # Chrome on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        
        # Firefox on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) Gecko/20100101 Firefox/121.0",
        
        # Safari on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        
        # Mobile browsers
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ]
    
    # Anomalous user agents (bots, tools, malware)
    anomalous_agents = [
        # Obvious bots
        "python-requests/2.31.0",
        "curl/7.68.0",
        "wget/1.20.3",
        "Java/1.8.0_181",
        "Python-urllib/3.9",
        
        # Headless browsers
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Puppeteer",
        
        # Web scrapers
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Scrapy/2.11.0 (+https://scrapy.org)",
        
        # Malformed/suspicious
        "Mozilla/5.0",  # Too short
        "Chrome",  # Just browser name
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",  # Missing parts
        
        # Old/outdated (potential malware)
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",  # Very old Firefox
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",  # Windows XP
        
        # Security tools
        "sqlmap/1.4.12#stable (http://sqlmap.org)",
        "Nikto/2.1.6",
        
        # Random/generated
        "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789/. ", k=50)),
        "Mozilla/5.0 " + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=20)),
    ]
    
    # Generate training data
    normal_data = []
    for _ in range(800):
        ua = random.choice(normal_agents)
        # Add slight variations
        if random.random() > 0.9:
            # Minor version changes
            parts = ua.split()
            for i, part in enumerate(parts):
                if "/" in part and any(c.isdigit() for c in part):
                    version_parts = part.split(".")
                    if len(version_parts) > 2 and version_parts[-1].isdigit():
                        version_parts[-1] = str(int(version_parts[-1]) + random.randint(-2, 2))
                        parts[i] = ".".join(version_parts)
                        break
            ua = " ".join(parts)
        
        normal_data.append({
            'userAgent': ua,
            'history': []
        })
    
    anomalous_data = []
    for _ in range(200):
        ua = random.choice(anomalous_agents)
        if ua.startswith("Mozilla/5.0 "):
            # Sometimes add random stuff to make it more suspicious
            if random.random() > 0.5:
                ua += " " + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10))
        
        anomalous_data.append({
            'userAgent': ua,
            'history': []
        })
    
    return {
        'normal': normal_data,
        'anomalous': anomalous_data
    }


def train_useragent_model():
    """Train and save the user agent risk model."""
    print("Training UserAgent Risk Model...")
    
    # Generate training data
    training_data = generate_useragent_training_data()
    
    # Initialize model
    model = UserAgentRiskModel()
    
    # Train model
    model.train(training_data)
    
    # Save model
    model.save_model()
    
    # Test the model
    print("\nTesting UserAgent Risk Model:")
    
    # Test normal Chrome browser
    test_normal = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'timestamp': 1703001600000
    }
    score = model.predict(test_normal, [])
    print(f"Normal Chrome browser score: {score}")
    
    # Test Python requests (bot)
    test_bot = {
        'ip': '192.168.1.1',
        'userAgent': 'python-requests/2.31.0',
        'timestamp': 1703001600000
    }
    score = model.predict(test_bot, [])
    print(f"Python requests bot score: {score}")
    
    # Test headless Chrome
    test_headless = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
        'timestamp': 1703001600000
    }
    score = model.predict(test_headless, [])
    print(f"Headless Chrome score: {score}")
    
    # Test malformed user agent
    test_malformed = {
        'ip': '192.168.1.1',
        'userAgent': 'Mozilla/5.0',
        'timestamp': 1703001600000
    }
    score = model.predict(test_malformed, [])
    print(f"Malformed user agent score: {score}")
    
    print("\nUserAgent Risk Model training complete!")


if __name__ == "__main__":
    train_useragent_model()