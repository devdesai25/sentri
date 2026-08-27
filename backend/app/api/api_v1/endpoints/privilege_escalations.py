from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.db.crud.privilege_escalations import privilege_escalation
from app.schemas.privilege_escalation import (
    PrivilegeEscalation,
    PrivilegeEscalationCreate,
    PrivilegeEscalationUpdate,
    PrivilegeEscalationSearch,
    EscalationMethod
)

# Create router with prefix and tags for OpenAPI docs
router = APIRouter(prefix="/privilege-escalations", tags=["privilege"])


@router.post("/", response_model=PrivilegeEscalation, status_code=status.HTTP_201_CREATED)
async def create_privilege_escalation(
    event_in: PrivilegeEscalationCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new privilege escalation event.
    
    This endpoint is primarily used by the Sentri agent to report privilege escalation events.
    """
    event = await privilege_escalation.create(db=db, obj_in=event_in)
    return event


@router.get("/", response_model=List[PrivilegeEscalation])
async def list_privilege_escalations(
    db: AsyncSession = Depends(get_db_session),
    username: Optional[str] = None,
    target_user: Optional[str] = None,
    method: Optional[EscalationMethod] = None,
    success: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    Retrieve privilege escalation events with optional filtering.
    
    - Filter by username, target user, method, and success status
    - Limit time range with start_time and end_time
    - Use skip and limit for pagination
    """
    # Create search parameters from query parameters
    search_params = PrivilegeEscalationSearch(
        username=username,
        target_user=target_user,
        method=method,
        success=success,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=skip
    )
    
    # Get events matching criteria
    events = await privilege_escalation.search(db=db, search_params=search_params)
    return events


@router.get("/stats", response_model=Dict[str, Any])
async def get_privilege_escalation_stats(
    db: AsyncSession = Depends(get_db_session),
    start_time: Optional[datetime] = Query(None, description="Start time for stats period"),
    end_time: Optional[datetime] = Query(None, description="End time for stats period"),
    lookback_hours: Optional[int] = Query(None, ge=1, le=720, description="Look back N hours")
):
    """
    Get statistics about privilege escalation events.
    
    - Provide summary of events, users, methods, and success rates
    - Filter by time period using start_time and end_time
    - Use lookback_hours for quick relative time ranges
    """
    # Handle lookback_hours parameter
    if lookback_hours and not start_time:
        start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
    
    stats = await privilege_escalation.get_stats(
        db=db,
        start_time=start_time,
        end_time=end_time
    )
    
    return stats


@router.get("/{event_id}", response_model=PrivilegeEscalation)
async def get_privilege_escalation(
    event_id: int = Path(..., title="The ID of the privilege escalation event to get"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Retrieve a specific privilege escalation event by ID.
    """
    event = await privilege_escalation.get(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Privilege escalation event with ID {event_id} not found"
        )
    return event


@router.delete("/{event_id}", response_model=PrivilegeEscalation)
async def delete_privilege_escalation(
    event_id: int = Path(..., title="The ID of the privilege escalation event to delete"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a specific privilege escalation event by ID.
    """
    event = await privilege_escalation.remove(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Privilege escalation event with ID {event_id} not found"
        )
    return event