from fastapi import APIRouter, Query, HTTPException, status, BackgroundTasks
from typing import Dict, Any, Optional

from app.services.telegram_service import TelegramService
from app.core.config import settings
from datetime import datetime

router = APIRouter(prefix="/ssh-security", tags=["ssh-security"])

@router.post("/brute-force-alert", response_model=Dict[str, Any])
async def send_brute_force_alert(
    ip_address: str,
    username: str,
    failure_count: int,
    threshold: int = Query(..., description="The threshold that was exceeded"),
    is_blocked: bool = Query(..., description="Whether the IP was blocked"),
    block_minutes: Optional[int] = Query(0, description="Duration of the block in minutes"),
    background_tasks: BackgroundTasks = None
):
    """
    Send alert about SSH brute force attack to configured notification channels.
    
    This endpoint is called by the Sentri agent when it detects and blocks
    a potential brute force attack against SSH.
    """
    telegram_service = TelegramService()
    
    # Add notification task to background to avoid blocking response
    if background_tasks:
        background_tasks.add_task(
            telegram_service.send_brute_force_alert,
            ip_address=ip_address,
            username=username,
            failure_count=failure_count,
            threshold=threshold,
            is_blocked=is_blocked,
            block_minutes=block_minutes
        )
        
        return {
            "status": "notification_queued",
            "timestamp": datetime.now().isoformat()
        }
    else:
        # Send notification directly if no background tasks available
        success = await telegram_service.send_brute_force_alert(
            ip_address=ip_address,
            username=username,
            failure_count=failure_count,
            threshold=threshold,
            is_blocked=is_blocked,
            block_minutes=block_minutes
        )
        
        if success:
            return {
                "status": "notification_sent",
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send notification"
            )