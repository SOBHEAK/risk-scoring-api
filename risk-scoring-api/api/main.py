# api/main.py
import time
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import motor.motor_asyncio
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, generate_latest
from fastapi.responses import PlainTextResponse

from api.models import AnalyzeRequest, AnalyzeResponse, HealthResponse, MetaResponse, ScoresResponse
from api.auth import verify_api_key
from api.validators import validate_ip_address, validate_timestamp
from config.settings import get_settings
from ml_models.ip_model import IPRiskModel
from ml_models.datetime_model import DateTimeRiskModel
from ml_models.useragent_model import UserAgentRiskModel
from ml_models.geolocation_model import GeolocationRiskModel

# Initialize settings
settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' if settings.log_format == 'text' else None
)
logger = logging.getLogger(__name__)

# Prometheus metrics
request_count = Counter('risk_api_requests_total', 'Total API requests', ['endpoint', 'status'])
request_duration = Histogram('risk_api_request_duration_seconds', 'Request duration', ['endpoint'])
model_inference_duration = Histogram('model_inference_duration_seconds', 'Model inference duration', ['model'])

# Global variables for models and connections
models: Dict[str, any] = {}
mongodb_client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
redis_client: Optional[redis.Redis] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global models, mongodb_client, redis_client
    
    logger.info("Starting Xayone Risk Scoring API...")
    
    # Load ML models
    logger.info("Loading ML models...")
    try:
        models['ip'] = IPRiskModel()
        models['datetime'] = DateTimeRiskModel()
        models['useragent'] = UserAgentRiskModel()
        models['geolocation'] = GeolocationRiskModel()
        
        # Load saved models
        for name, model in models.items():
            if model.load_model():
                logger.info(f"{name} model loaded successfully")
            else:
                logger.warning(f"{name} model not found, will use rule-based scoring")
    except Exception as e:
        logger.error(f"Error loading models: {e}")
    
    # Initialize MongoDB
    try:
        mongodb_client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.mongodb_url,
            maxPoolSize=settings.mongodb_max_pool_size
        )
        # Test connection
        await mongodb_client.admin.command('ping')
        logger.info("MongoDB connected successfully")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        mongodb_client = None
    
    # Initialize Redis
    try:
        redis_client = await redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        await redis_client.ping()
        logger.info("Redis connected successfully")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        redis_client = None
    
    logger.info("API startup complete")
    
    yield
    
    # Cleanup
    logger.info("Shutting down API...")
    if mongodb_client:
        mongodb_client.close()
    if redis_client:
        await redis_client.close()
    logger.info("API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Rate limiting
async def check_rate_limit(api_key: str) -> bool:
    """Check if API key has exceeded rate limit."""
    if not redis_client:
        return True  # Allow if Redis is not available
    
    key = f"rate_limit:{api_key}"
    try:
        current = await redis_client.incr(key)
        if current == 1:
            await redis_client.expire(key, 60)  # 1 minute window
        return current <= settings.max_requests_per_minute
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")
        return True  # Allow on error


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=int(time.time() * 1000),
        version=settings.api_version,
        models_loaded=all(model.is_loaded for model in models.values()),
        database_connected=mongodb_client is not None,
        redis_connected=redis_client is not None
    )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return PlainTextResponse(generate_latest())


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_risk(
    request: AnalyzeRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Analyze login risk based on current session and history.
    
    Returns risk scores from 0-100 for different factors.
    """
    start_time = time.time()
    request_id = f"req_{uuid.uuid4()}"
    
    # Rate limiting
    if not await check_rate_limit(api_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    # Validate inputs
    if not validate_ip_address(request.currentSession.ip):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address"
        )
    
    if not validate_timestamp(request.currentSession.timestamp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp"
        )
    
    try:
        # Check cache first
        cache_key = f"risk_score:{request.userId}:{request.currentSession.ip}:{request.currentSession.userAgent[:50]}"
        if redis_client:
            cached_result = await redis_client.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for {cache_key}")
                return JSONResponse(content=eval(cached_result))
        
        # Convert request to dict for models
        current_session = request.currentSession.model_dump()
        login_history = [item.model_dump() for item in request.loginHistory]
        
        # Run models in parallel
        with request_duration.labels(endpoint="analyze").time():
            tasks = []
            for model_name, model in models.items():
                task = asyncio.create_task(
                    run_model_async(model_name, model, current_session, login_history)
                )
                tasks.append(task)
            
            scores_list = await asyncio.gather(*tasks)
            
            # Create scores dict
            scores_dict = {}
            for model_name, score in scores_list:
                scores_dict[model_name] = score
            
            # Calculate overall score
            overall_score = int(
                scores_dict['ip'] * 0.30 +
                scores_dict['datetime'] * 0.20 +
                scores_dict['useragent'] * 0.25 +
                scores_dict['geolocation'] * 0.25
            )
            
            # Create response
            processing_time = int((time.time() - start_time) * 1000)
            
            response = AnalyzeResponse(
                meta=MetaResponse(
                    requestId=request_id,
                    userId=request.userId,
                    timestamp=int(time.time() * 1000),
                    processingTime=processing_time,
                    modelsVersion=settings.model_version
                ),
                scores=ScoresResponse(
                    ip=scores_dict['ip'],
                    datetime=scores_dict['datetime'],
                    userAgent=scores_dict['useragent'],
                    geolocation=scores_dict['geolocation'],
                    overall=overall_score
                )
            )
            
            # Cache result
            if redis_client:
                await redis_client.setex(
                    cache_key,
                    settings.redis_cache_ttl,
                    response.model_dump_json()
                )
            
            # Store in MongoDB for future analysis
            if mongodb_client:
                db = mongodb_client[settings.mongodb_db_name]
                await db.risk_scores.insert_one({
                    "requestId": request_id,
                    "userId": request.userId,
                    "timestamp": datetime.utcnow(),
                    "currentSession": current_session,
                    "scores": response.scores.model_dump(),
                    "processingTime": processing_time
                })
            
            # Update metrics
            request_count.labels(endpoint="analyze", status="success").inc()
            
            return response
            
    except Exception as e:
        logger.error(f"Error analyzing risk: {e}")
        request_count.labels(endpoint="analyze", status="error").inc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


async def run_model_async(model_name: str, model: any, 
                         current_session: Dict, login_history: List[Dict]) -> tuple:
    """Run model prediction asynchronously."""
    loop = asyncio.get_event_loop()
    
    with model_inference_duration.labels(model=model_name).time():
        # Run CPU-bound model prediction in thread pool
        score = await loop.run_in_executor(
            None,
            model.predict,
            current_session,
            login_history
        )
    
    return (model_name, score)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": int(time.time() * 1000)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": int(time.time() * 1000)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )