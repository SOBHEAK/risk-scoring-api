# Xayone Risk Scoring API

A production-ready ML-powered risk scoring API that analyzes user login attempts and returns risk scores to help detect suspicious authentication attempts.

## Features

- **Four ML Models** for comprehensive risk analysis:
  - **IP Risk Model** (One-Class SVM): Detects VPNs, proxies, Tor, datacenter IPs
  - **DateTime Risk Model** (Isolation Forest): Identifies unusual login times and patterns
  - **UserAgent Risk Model** (Autoencoder): Detects bots, headless browsers, and spoofed agents
  - **Geolocation Risk Model** (DBSCAN): Validates impossible travel and location anomalies

- **High Performance**:
  - Handles 1000+ requests/second
  - Response time < 200ms
  - Redis caching for repeated requests
  - Async processing with FastAPI

- **Production Ready**:
  - Docker containerization
  - MongoDB for data persistence
  - API key authentication
  - Rate limiting (100 requests/minute per key)
  - Prometheus metrics
  - Comprehensive logging
  - Health check endpoints

## Quick Start

### Using Docker (Recommended)

1. Clone the repository
```bash
git clone <repository-url>
cd risk-scoring-api
```

2. Copy environment file
```bash
cp .env.example .env
# Edit .env with your settings
```

3. Start all services
```bash
docker-compose up -d
```

4. Train the models (first time only)
```bash
docker-compose --profile training run train-models
```

The API will be available at `http://localhost:8000`

### Local Development

1. Install dependencies
```bash
pip install -r requirements.txt
```

2. Train models
```bash
python -m training.train_all_models
```

3. Start services (MongoDB and Redis)
```bash
docker-compose up mongodb redis -d
```

4. Run the API
```bash
uvicorn api.main:app --reload
```

## API Usage

### Authentication

All API requests require an API key in the header:
```bash
X-API-Key: your-api-key-here
```

### Analyze Endpoint

**POST** `/api/v1/analyze`

#### Request Body
```json
{
  "currentSession": {
    "ip": "73.123.45.67",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "timestamp": 1703001600000,
    "timezone": "America/New_York",
    "screenResolution": "1920x1080",
    "platform": "Win32"
  },
  "loginHistory": [
    {
      "ip": "73.123.45.67",
      "userAgent": "Mozilla/5.0...",
      "timestamp": 1702915200000,
      "location": {
        "country": "United States",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060
      },
      "loginStatus": "success"
    }
  ],
  "userId": "user@example.com"
}
```

#### Response
```json
{
  "meta": {
    "requestId": "req_550e8400-e29b-41d4-a716-446655440000",
    "userId": "user@example.com",
    "timestamp": 1703001600000,
    "processingTime": 145,
    "modelsVersion": "v1.0.0"
  },
  "scores": {
    "ip": 15,
    "datetime": 10,
    "userAgent": 5,
    "geolocation": 20,
    "overall": 13
  }
}
```

### Risk Score Interpretation

- **0-30**: Low risk (normal behavior)
- **31-70**: Medium risk (unusual activity)
- **71-100**: High risk (likely attack)

### Example: Normal Login
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: xayone_test_key_123" \
  -d '{
    "currentSession": {
      "ip": "73.123.45.67",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      "timestamp": 1703001600000
    },
    "loginHistory": [],
    "userId": "test@example.com"
  }'
```

## ML Models Details

### IP Risk Model
- **Algorithm**: One-Class SVM
- **Features**: IP type, datacenter detection, historical IPs, geographic distribution
- **High Risk**: VPN/proxy IPs, Tor exit nodes, blacklisted sources
- **Training**: Public threat feeds and IP reputation data

### DateTime Risk Model
- **Algorithm**: Isolation Forest
- **Features**: Hour of day, day of week, login velocity, burst patterns
- **High Risk**: 3AM logins for day users, rapid attempts, unusual patterns
- **Training**: Synthetic normal vs attack patterns

### UserAgent Risk Model
- **Algorithm**: Autoencoder Neural Network
- **Features**: Browser family, OS, device type, entropy, bot patterns
- **High Risk**: Headless browsers, bots, malformed agents
- **Training**: Real browser data vs bot patterns

### Geolocation Risk Model
- **Algorithm**: DBSCAN clustering + physics validation
- **Features**: Location clusters, travel speed, country risk
- **High Risk**: Impossible travel, high-risk countries
- **Validation**: Max travel speed 900 km/h

## Testing

Run the test suite:
```bash
# All tests
pytest

# Specific test file
pytest tests/test_api.py -v

# With coverage
pytest --cov=api --cov=ml_models tests/
```

## Test Scenarios

The API correctly identifies these attack patterns:

1. **VPN/Proxy Usage**: IP score 70-90
2. **Bot Attempts**: UserAgent score 80-100
3. **Impossible Travel**: Geolocation score 85-100
4. **Midnight Attacks**: DateTime score 70-85
5. **Credential Stuffing**: High datetime + IP scores

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

### Prometheus Metrics
```bash
# Enable monitoring profile
docker-compose --profile monitoring up -d

# Access Prometheus at http://localhost:9090
```

### Key Metrics
- `risk_api_requests_total`: Total API requests
- `risk_api_request_duration_seconds`: Request latency
- `model_inference_duration_seconds`: Model performance

## Performance Optimization

1. **Redis Caching**: Repeated requests are cached for 5 minutes
2. **Parallel Model Execution**: All models run concurrently
3. **Connection Pooling**: MongoDB connections are pooled
4. **Async Processing**: Non-blocking I/O operations

## Production Deployment

### Environment Variables
```bash
API_KEYS=prod_key_1,prod_key_2
SECRET_KEY=strong-secret-key
MONGODB_URL=mongodb://user:pass@host:27017
REDIS_URL=redis://user:pass@host:6379
LOG_LEVEL=INFO
WORKER_COUNT=8
```

### Scaling
```bash
# Scale API containers
docker-compose up -d --scale api=4
```

### Security Considerations
- Always use HTTPS in production
- Rotate API keys regularly
- Enable MongoDB authentication
- Use Redis password
- Monitor rate limits
- Enable audit logging

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Client    │────▶│  API Gateway │────▶│   FastAPI   │
└─────────────┘     └──────────────┘     └─────────────┘
                                                 │
                                    ┌────────────┼────────────┐
                                    │            │            │
                                    ▼            ▼            ▼
                            ┌─────────────┐ ┌────────┐ ┌─────────┐
                            │  ML Models  │ │ Redis  │ │ MongoDB │
                            └─────────────┘ └────────┘ └─────────┘
```

## Troubleshooting

### Models not loading
```bash
# Retrain models
docker-compose --profile training run train-models
```

### High response times
- Check Redis connection
- Verify model files exist in ./models
- Monitor CPU usage

### API errors
- Check logs: `docker-compose logs api`
- Verify MongoDB/Redis are running
- Validate API key format

## License

Copyright (c) 2024 Xayone. All rights reserved.