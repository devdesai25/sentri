from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.db.crud.events import ssh_event
from app.schemas.event import (
    SSHEvent, 
    SSHEventCreate, 
    SSHEventUpdate,
    SSHEventSearch,
    SSHEventStatistics,
    EventType, 
    AuthMethod
)

# Create router with prefix and tags for OpenAPI docs
router = APIRouter(prefix="/ssh", tags=["ssh"])


@router.post("/events", response_model=SSHEvent, status_code=status.HTTP_201_CREATED)
async def create_ssh_event(
    event_in: SSHEventCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new SSH event.
    
    This endpoint is primarily used by the Sentri agent to report SSH login events.
    """
    event = await ssh_event.create(db=db, obj_in=event_in)
    return event


@router.get("/events", response_model=List[SSHEvent])
async def list_ssh_events(
    db: AsyncSession = Depends(get_db_session),
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[List[EventType]] = Query(None),
    auth_method: Optional[List[AuthMethod]] = Query(None),
    success: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    Retrieve SSH events with optional filtering.
    
    - Filter by username, source IP, event type, auth method, and success status
    - Limit time range with start_time and end_time
    - Use skip and limit for pagination
    """
    # Create search parameters from query parameters
    search_params = SSHEventSearch(
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        auth_method=auth_method,
        success=success,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=skip
    )
    
    # Get events matching criteria
    events = await ssh_event.search(db=db, search_params=search_params)
    return events


@router.get("/events/stats", response_model=SSHEventStatistics)
async def get_ssh_event_stats(
    db: AsyncSession = Depends(get_db_session),
    start_time: Optional[datetime] = Query(None, description="Start time for stats period"),
    end_time: Optional[datetime] = Query(None, description="End time for stats period"),
    lookback_hours: Optional[int] = Query(None, ge=1, le=720, description="Look back N hours")
):
    """
    Get statistics about SSH events.
    
    - Provide summary of events, users, IPs, and authentication methods
    - Filter by time period using start_time and end_time
    - Use lookback_hours for quick relative time ranges
    """
    # Handle lookback_hours parameter
    if lookback_hours and not start_time:
        start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
    
    stats = await ssh_event.get_stats(
        db=db,
        start_time=start_time,
        end_time=end_time
    )
    
    return SSHEventStatistics(**stats)


@router.get("/events/{event_id}", response_model=SSHEvent)
async def get_ssh_event(
    event_id: int = Path(..., title="The ID of the SSH event to get"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Retrieve a specific SSH event by ID.
    """
    event = await ssh_event.get(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSH event with ID {event_id} not found"
        )
    return event


@router.delete("/events/{event_id}", response_model=SSHEvent)
async def delete_ssh_event(
    event_id: int = Path(..., title="The ID of the SSH event to delete"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a specific SSH event by ID.
    """
    event = await ssh_event.remove(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSH event with ID {event_id} not found"
        )
    return event