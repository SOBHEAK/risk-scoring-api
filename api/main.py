"""
Main FastAPI application for Xayone Risk Scoring API
"""
import asyncio
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import uuid
import time
import logging
from typing import Dict, Any
import redis.asyncio as redis
from motor.motor_asyncio import AsyncIOMotorClient
import json

from api.models import (
    AnalyzeRequest, AnalyzeResponse, HealthResponse, 
    ErrorResponse, RiskScores, ResponseMeta
)
from api.auth import verify_api_key
from api.validators import validate_ip_address, validate_timestamp, sanitize_input
from config.settings import settings
from ml_models.ip_model import IPRiskModel
from ml_models.datetime_model import DateTimeRiskModel
from ml_models.useragent_model import UserAgentRiskModel
from ml_models.geolocation_model import GeolocationRiskModel
from utils.ip_utils import IPAnalyzer
from utils.geo_utils import GeoLocationAnalyzer

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for connections and models
redis_client = None
mongodb_client = None
mongodb_db = None
models = {}
ip_analyzer = None
geo_analyzer = None

# Rate limiting cache
rate_limit_cache = {}


async def get_redis_client():
    """Get Redis client"""
    global redis_client
    if not redis_client:
        redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return redis_client


async def get_mongodb_client():
    """Get MongoDB client"""
    global mongodb_client, mongodb_db
    if not mongodb_client:
        mongodb_client = AsyncIOMotorClient(settings.MONGODB_URL)
        mongodb_db = mongodb_client[settings.MONGODB_DB_NAME]
    return mongodb_db


@app.on_event("startup")
async def startup_event():
    """Initialize models and connections on startup"""
    global models, ip_analyzer, geo_analyzer
    
    logger.info("Starting Xayone Risk Scoring API...")
    
    # Initialize analyzers
    ip_analyzer = IPAnalyzer()
    geo_analyzer = GeoLocationAnalyzer()
    
    # Load ML models
    try:
        # Initialize models
        models['ip'] = IPRiskModel(f"{settings.MODELS_PATH}/ip_model.pkl")
        models['datetime'] = DateTimeRiskModel(f"{settings.MODELS_PATH}/datetime_model.pkl")
        models['useragent'] = UserAgentRiskModel(f"{settings.MODELS_PATH}/useragent_model.pkl")
        models['geolocation'] = GeolocationRiskModel(f"{settings.MODELS_PATH}/geolocation_model.pkl")
        
        # Try to load pre-trained models
        for name, model in models.items():
            try:
                model.load_model()
                logger.info(f"Loaded {name} model")
            except FileNotFoundError:
                logger.warning(f"Pre-trained {name} model not found, will use untrained model")
            except Exception as e:
                logger.error(f"Error loading {name} model: {e}")
                
    except Exception as e:
        logger.error(f"Error initializing models: {e}")
        
    # Test connections
    try:
        await get_redis_client()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        
    try:
        await get_mongodb_client()
        logger.info("MongoDB connection established")
    except Exception as e:
        logger.warning(f"MongoDB connection failed: {e}")
        
    logger.info("API startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global redis_client, mongodb_client
    
    if redis_client:
        redis_client.close()
        
    if mongodb_client:
        mongodb_client.close()
        
    logger.info("API shutdown complete")


async def check_rate_limit(api_key: str, request: Request) -> bool:
    """Check if request exceeds rate limit"""
    client_ip = request.client.host
    cache_key = f"rate_limit:{api_key}:{client_ip}"
    
    try:
        r = await get_redis_client()
        current = await r.incr(cache_key)
        
        if current == 1:
            await r.expire(cache_key, settings.RATE_LIMIT_PERIOD)
            
        return current <= settings.RATE_LIMIT_REQUESTS
    except:
        # Fallback to in-memory rate limiting
        current_time = time.time()
        if cache_key not in rate_limit_cache:
            rate_limit_cache[cache_key] = []
            
        # Clean old entries
        rate_limit_cache[cache_key] = [
            t for t in rate_limit_cache[cache_key] 
            if current_time - t < settings.RATE_LIMIT_PERIOD
        ]
        
        rate_limit_cache[cache_key].append(current_time)
        return len(rate_limit_cache[cache_key]) <= settings.RATE_LIMIT_REQUESTS


async def get_location_from_ip(ip: str) -> Dict[str, Any]:
    """Get geolocation from IP address"""
    # In production, this would use MaxMind GeoIP2 or similar
    # For now, return mock data based on IP pattern
    
    if ip.startswith('192.168') or ip.startswith('10.'):
        return {
            'country': 'Private Network',
            'city': 'Local',
            'latitude': 0.0,
            'longitude': 0.0
        }
    
    # Mock locations for testing
    if ip.startswith('8.8'):
        return {
            'country': 'United States',
            'city': 'Mountain View',
            'latitude': 37.4056,
            'longitude': -122.0775
        }
    
    # Default location
    return {
        'country': 'United States',
        'city': 'New York',
        'latitude': 40.7128,
        'longitude': -74.0060
    }


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint"""
    return {
        "message": "Xayone Risk Scoring API",
        "version": settings.VERSION,
        "docs": "/docs" if settings.DEBUG else "Disabled"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    redis_connected = False
    mongodb_connected = False
    
    try:
        r = await get_redis_client()
        await r.ping()
        redis_connected = True
    except:
        pass
        
    try:
        db = await get_mongodb_client()
        await db.command('ping')
        mongodb_connected = True
    except:
        pass
    
    models_loaded = all(model.is_loaded or model.model is not None 
                       for model in models.values())
    
    return HealthResponse(
        status="healthy" if models_loaded else "degraded",
        timestamp=int(time.time() * 1000),
        version=settings.VERSION,
        models_loaded=models_loaded,
        redis_connected=redis_connected,
        mongodb_connected=mongodb_connected
    )


@app.post(
    f"{settings.API_V1_STR}/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(verify_api_key)]
)
async def analyze_risk(
    request_data: AnalyzeRequest,
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """Analyze login risk and return risk scores"""
    start_time = time.time()
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    
    try:
        # Rate limiting
        if not await check_rate_limit(api_key, request):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Validate input
        if not validate_ip_address(request_data.currentSession.ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid IP address"
            )
            
        if not validate_timestamp(request_data.currentSession.timestamp):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid timestamp"
            )
        
        # Sanitize input
        current_session_dict = sanitize_input(request_data.currentSession.dict())
        login_history_dict = [sanitize_input(item.dict()) for item in request_data.loginHistory]
        
        # Get location for current session
        location = await get_location_from_ip(current_session_dict['ip'])
        
        # Prepare data for models
        model_input = {
            **current_session_dict,
            'location': location,
            'login_history': login_history_dict
        }
        
        # Run models in parallel
        tasks = []
        
        # IP Model
        tasks.append(asyncio.create_task(
            asyncio.to_thread(
                models['ip'].predict_risk,
                model_input,
                login_history_dict
            )
        ))
        
        # DateTime Model
        tasks.append(asyncio.create_task(
            asyncio.to_thread(
                models['datetime'].predict_risk,
                model_input,
                login_history_dict
            )
        ))
        
        # UserAgent Model
        tasks.append(asyncio.create_task(
            asyncio.to_thread(
                models['useragent'].predict_risk,
                model_input,
                login_history_dict
            )
        ))
        
        # Geolocation Model
        tasks.append(asyncio.create_task(
            asyncio.to_thread(
                models['geolocation'].predict_risk,
                model_input,
                login_history_dict
            )
        ))
        
        # Wait for all models to complete
        scores = await asyncio.gather(*tasks)
        
        # Calculate overall score
        overall_score = int(
            scores[0] * settings.IP_WEIGHT +
            scores[1] * settings.DATETIME_WEIGHT +
            scores[2] * settings.USERAGENT_WEIGHT +
            scores[3] * settings.GEOLOCATION_WEIGHT
        )
        
        # Ensure scores are within bounds
        risk_scores = RiskScores(
            ip=max(0, min(100, scores[0])),
            datetime=max(0, min(100, scores[1])),
            userAgent=max(0, min(100, scores[2])),
            geolocation=max(0, min(100, scores[3])),
            overall=max(0, min(100, overall_score))
        )
        
        # Store in MongoDB for future analysis
        try:
            db = await get_mongodb_client()
            await db.risk_scores.insert_one({
                'request_id': request_id,
                'user_id': request_data.userId,
                'timestamp': request_data.currentSession.timestamp,
                'scores': risk_scores.dict(),
                'ip': request_data.currentSession.ip,
                'user_agent': request_data.currentSession.userAgent
            })
        except Exception as e:
            logger.error(f"Failed to store in MongoDB: {e}")
        
        # Cache result
        try:
            r = await get_redis_client()
            cache_key = f"risk_score:{request_data.userId}:{request_data.currentSession.ip}"
            await r.setex(
                cache_key,
                settings.REDIS_CACHE_TTL,
                json.dumps(risk_scores.dict())
            )
        except Exception as e:
            logger.error(f"Failed to cache in Redis: {e}")
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        
        # Build response
        response = AnalyzeResponse(
            meta=ResponseMeta(
                requestId=request_id,
                userId=request_data.userId,
                timestamp=request_data.currentSession.timestamp,
                processingTime=processing_time,
                modelsVersion=settings.MODELS_VERSION
            ),
            scores=risk_scores
        )
        
        logger.info(f"Risk analysis completed for {request_data.userId}: {risk_scores.overall}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in risk analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during risk analysis"
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="HTTPException",
            message=exc.detail,
            timestamp=int(time.time() * 1000)
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred",
            timestamp=int(time.time() * 1000)
        ).dict()
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )