# Xayone Risk Scoring API

A production-ready risk scoring API that analyzes user login attempts and returns risk scores to help detect suspicious authentication attempts. The system uses four specialized ML models to analyze different risk factors without making authentication decisions.

## Features

- **High Performance**: Handles 1000+ requests/second with <200ms response time
- **Four ML Models**:
  - IP Risk Model (One-Class SVM): Detects VPNs, proxies, Tor, datacenter IPs
  - DateTime Risk Model (Isolation Forest): Detects unusual login times, brute force patterns
  - UserAgent Risk Model (Autoencoder): Detects bots, headless browsers, spoofed agents
  - Geolocation Risk Model (DBSCAN): Detects impossible travel, location anomalies
- **Production Ready**: Docker support, rate limiting, caching, monitoring
- **API Key Authentication**: Secure access control
- **Comprehensive Logging**: Detailed request/response logging

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/xayone/risk-scoring-api.git
cd risk-scoring-api
```

2. Copy environment variables:
```bash
cp .env.example .env
```

3. Train the ML models:
```bash
docker-compose --profile train up model-trainer
```

4. Start the services:
```bash
docker-compose up -d
```

The API will be available at `http://localhost:8000`

### Manual Installation

1. Install Python 3.9+

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Train models:
```bash
python training/train_ip_model.py
python training/train_datetime_model.py
python training/train_useragent_model.py
python training/train_geolocation_model.py
```

5. Start MongoDB and Redis:
```bash
# Using Docker
docker run -d -p 27017:27017 mongo:7.0
docker run -d -p 6379:6379 redis:7-alpine
```

6. Run the API:
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

## API Usage

### Authentication

Include your API key in the `X-API-Key` header:
```bash
X-API-Key: xayone-test-key-123
```

### Analyze Risk Endpoint

**POST** `/api/v1/analyze`

#### Request Body:
```json
{
  "currentSession": {
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "timestamp": 1703123456789,
    "screenResolution": "1920x1080",
    "timezone": "America/New_York",
    "platform": "Win32",
    "hardwareConcurrency": 8,
    "touchSupport": false,
    "isCookieEnabled": true
  },
  "loginHistory": [
    {
      "ip": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "timestamp": 1703123456789,
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

#### Response:
```json
{
  "meta": {
    "requestId": "req_abc123def456",
    "userId": "user@example.com",
    "timestamp": 1703123456789,
    "processingTime": 145,
    "modelsVersion": "v1.0.0"
  },
  "scores": {
    "ip": 15,
    "datetime": 22,
    "userAgent": 10,
    "geolocation": 18,
    "overall": 16
  }
}
```

### Risk Score Interpretation

- **0-30**: Low risk (normal behavior)
- **31-70**: Medium risk (unusual activity)
- **71-100**: High risk (likely attack)

### Health Check

**GET** `/health`

Returns API health status and connectivity to databases.

## Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Test Specific Scenarios

1. **Normal Login (Low Risk)**:
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: xayone-test-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "currentSession": {
      "ip": "73.45.123.45",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      "timestamp": 1703123456789
    },
    "loginHistory": [],
    "userId": "test@example.com"
  }'
```

2. **VPN Detection (High Risk)**:
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: xayone-test-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "currentSession": {
      "ip": "104.16.1.1",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      "timestamp": 1703123456789
    },
    "loginHistory": [],
    "userId": "test@example.com"
  }'
```

3. **Bot Detection (High Risk)**:
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: xayone-test-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "currentSession": {
      "ip": "192.168.1.1",
      "userAgent": "curl/7.64.1",
      "timestamp": 1703123456789
    },
    "loginHistory": [],
    "userId": "test@example.com"
  }'
```

## Configuration

### Environment Variables

See `.env.example` for all available configurations:

- `ALLOWED_API_KEYS`: Comma-separated list of valid API keys
- `RATE_LIMIT_REQUESTS`: Max requests per period (default: 100)
- `RATE_LIMIT_PERIOD`: Period in seconds (default: 60)
- `REDIS_CACHE_TTL`: Cache TTL in seconds (default: 300)

### Risk Score Weights

Adjust the importance of each model:
- `IP_WEIGHT`: 0.30 (30%)
- `DATETIME_WEIGHT`: 0.20 (20%)
- `USERAGENT_WEIGHT`: 0.25 (25%)
- `GEOLOCATION_WEIGHT`: 0.25 (25%)

## Model Details

### IP Risk Model
- **Algorithm**: One-Class SVM
- **Features**: IP type, datacenter detection, VPN/proxy detection, historical patterns
- **Training**: Uses legitimate IP patterns to detect anomalies

### DateTime Risk Model
- **Algorithm**: Isolation Forest
- **Features**: Hour of day, day of week, login frequency, time patterns
- **Training**: Learns normal login time patterns

### UserAgent Risk Model
- **Algorithm**: Autoencoder Neural Network
- **Features**: Browser family, OS, device type, version consistency
- **Training**: Learns to reconstruct legitimate user agents

### Geolocation Risk Model
- **Algorithm**: DBSCAN Clustering
- **Features**: Location coordinates, travel speed, country patterns
- **Validation**: Physics-based impossible travel detection

## Performance Optimization

1. **Redis Caching**: Results cached for 5 minutes
2. **Parallel Model Execution**: All models run concurrently
3. **Connection Pooling**: Efficient database connections
4. **Async Processing**: Non-blocking I/O operations

## Monitoring

- Health endpoint: `/health`
- Logs: Available in `./logs` directory
- Metrics: Processing time included in responses

## Security Considerations

1. **API Key Rotation**: Regularly rotate API keys
2. **Rate Limiting**: Prevents abuse
3. **Input Validation**: All inputs sanitized
4. **No PII Storage**: Only stores minimal data for analysis

## Deployment

### Production Checklist

- [ ] Set strong API keys in production
- [ ] Configure external IP reputation services
- [ ] Set up log aggregation
- [ ] Configure monitoring alerts
- [ ] Enable HTTPS/TLS
- [ ] Set up backup strategy
- [ ] Configure auto-scaling

### Scaling

For high traffic:
1. Use multiple API instances behind load balancer
2. Use Redis cluster for caching
3. Use MongoDB replica set
4. Consider model serving infrastructure (TensorFlow Serving)

## Contributing

1. Fork the repository
2. Create feature branch
3. Run tests
4. Submit pull request

## License

Copyright (c) 2024 Xayone. All rights reserved.

## Support

For issues or questions:
- GitHub Issues: https://github.com/xayone/risk-scoring-api/issues
- Email: support@xayone.com