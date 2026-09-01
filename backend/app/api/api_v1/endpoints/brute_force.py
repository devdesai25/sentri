from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.db.crud.brute_force_attempts import brute_force_attempt
from app.schemas.brute_force import (
    BruteForceAttempt,
    BruteForceAttemptCreate,
    BruteForceAttemptUpdate,
    BruteForceAttemptSearch
)

# Create router with prefix and tags for OpenAPI docs
router = APIRouter(prefix="/brute-force", tags=["security"])


@router.post("/", response_model=BruteForceAttempt, status_code=status.HTTP_201_CREATED)
async def create_brute_force_attempt(
    event_in: BruteForceAttemptCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new brute force attempt event.
    
    This endpoint is primarily used by the Sentri agent to report brute force attack attempts.
    """
    event = await brute_force_attempt.create(db=db, obj_in=event_in)
    return event


@router.get("/", response_model=List[BruteForceAttempt])
async def list_brute_force_attempts(
    db: AsyncSession = Depends(get_db_session),
    source_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    blocked: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    Retrieve brute force attempt events with optional filtering.
    
    - Filter by source IP, target username, and blocked status
    - Limit time range with start_time and end_time
    - Use skip and limit for pagination
    """
    # Create search parameters from query parameters
    search_params = BruteForceAttemptSearch(
        source_ip=source_ip,
        target_username=target_username,
        blocked=blocked,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=skip
    )
    
    # Get events matching criteria
    events = await brute_force_attempt.search(db=db, search_params=search_params)
    return events


@router.get("/stats", response_model=Dict[str, Any])
async def get_brute_force_attempt_stats(
    db: AsyncSession = Depends(get_db_session),
    start_time: Optional[datetime] = Query(None, description="Start time for stats period"),
    end_time: Optional[datetime] = Query(None, description="End time for stats period"),
    lookback_hours: Optional[int] = Query(None, ge=1, le=720, description="Look back N hours")
):
    """
    Get statistics about brute force attempt events.
    
    - Provide summary of events, source IPs, target usernames, and blocking stats
    - Filter by time period using start_time and end_time
    - Use lookback_hours for quick relative time ranges
    """
    # Handle lookback_hours parameter
    if lookback_hours and not start_time:
        start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
    
    stats = await brute_force_attempt.get_stats(
        db=db,
        start_time=start_time,
        end_time=end_time
    )
    
    return stats


@router.get("/{event_id}", response_model=BruteForceAttempt)
async def get_brute_force_attempt(
    event_id: int = Path(..., title="The ID of the brute force attempt event to get"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Retrieve a specific brute force attempt event by ID.
    """
    event = await brute_force_attempt.get(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Brute force attempt event with ID {event_id} not found"
        )
    return event


@router.delete("/{event_id}", response_model=BruteForceAttempt)
async def delete_brute_force_attempt(
    event_id: int = Path(..., title="The ID of the brute force attempt event to delete"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a specific brute force attempt event by ID.
    """
    event = await brute_force_attempt.remove(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Brute force attempt event with ID {event_id} not found"
        )
    return event