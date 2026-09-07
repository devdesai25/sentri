from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.db.crud.command_executions import command_execution
from app.schemas.command_execution import (
    CommandExecution,
    CommandExecutionCreate,
    CommandExecutionUpdate,
    CommandExecutionSearch,
)

# Create router with prefix and tags for OpenAPI docs
router = APIRouter(prefix="/command-executions", tags=["commands"])


@router.post("/", response_model=CommandExecution, status_code=status.HTTP_201_CREATED)
async def create_command_execution(
    event_in: CommandExecutionCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new command execution event.
    
    This endpoint is primarily used by the Sentri agent to report command execution events.
    """
    event = await command_execution.create(db=db, obj_in=event_in)
    return event


@router.get("/", response_model=List[CommandExecution])
async def list_command_executions(
    db: AsyncSession = Depends(get_db_session),
    username: Optional[str] = None,
    host: Optional[str] = None,
    command: Optional[str] = None,
    risk_level: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100
):
    """
    Retrieve command execution events with optional filtering.
    
    - Filter by username, host, command pattern, and risk level
    - Limit time range with start_time and end_time
    - Use skip and limit for pagination
    """
    # Create search parameters from query parameters
    search_params = CommandExecutionSearch(
        username=username,
        host=host,
        command=command,
        risk_level=risk_level,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=skip
    )
    
    # Get events matching criteria
    events = await command_execution.search(db=db, search_params=search_params)
    return events


@router.get("/stats", response_model=Dict[str, Any])
async def get_command_execution_stats(
    db: AsyncSession = Depends(get_db_session),
    start_time: Optional[datetime] = Query(None, description="Start time for stats period"),
    end_time: Optional[datetime] = Query(None, description="End time for stats period"),
    lookback_hours: Optional[int] = Query(None, ge=1, le=720, description="Look back N hours")
):
    """
    Get statistics about command execution events.
    
    - Provide summary of events, users, hosts, and risk levels
    - Filter by time period using start_time and end_time
    - Use lookback_hours for quick relative time ranges
    """
    # Handle lookback_hours parameter
    if lookback_hours and not start_time:
        start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
    
    stats = await command_execution.get_stats(
        db=db,
        start_time=start_time,
        end_time=end_time
    )
    
    return stats


@router.get("/{event_id}", response_model=CommandExecution)
async def get_command_execution(
    event_id: int = Path(..., title="The ID of the command execution event to get"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Retrieve a specific command execution event by ID.
    """
    event = await command_execution.get(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Command execution event with ID {event_id} not found"
        )
    return event


@router.delete("/{event_id}", response_model=CommandExecution)
async def delete_command_execution(
    event_id: int = Path(..., title="The ID of the command execution event to delete"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a specific command execution event by ID.
    """
    event = await command_execution.remove(db=db, id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Command execution event with ID {event_id} not found"
        )
    return event