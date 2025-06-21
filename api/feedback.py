"""
Feedback endpoint for continuous learning
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


class FeedbackRequest(BaseModel):
    request_id: str
    was_legitimate: bool
    was_account_compromised: bool = False
    feedback_source: str = "manual_review"
    notes: Optional[str] = ""


class FeedbackResponse(BaseModel):
    success: bool
    message: str


@router.post("/api/v1/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackRequest,
    api_key: str = None  # Simplified for now
):
    """Submit feedback for a risk assessment to improve models"""
    # This will be connected to MongoDB in production
    logger.info(f"Received feedback for request {feedback.request_id}")
    
    # In production, this would update the database
    # For now, just log and return success
    
    return FeedbackResponse(
        success=True,
        message=f"Feedback recorded for request {feedback.request_id}"
    )