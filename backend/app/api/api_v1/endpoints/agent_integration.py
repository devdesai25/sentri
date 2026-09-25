from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any

from app.api.deps import get_db_session
from app.db.crud.events import ssh_event
from app.schemas.event import SSHEventCreate, SSHEvent

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/report", response_model=Dict[str, Any])
async def report_ssh_events(
    events: List[SSHEventCreate] = Body(...),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Endpoint for the agent to report multiple SSH events at once.
    
    This bulk endpoint allows the agent to efficiently send multiple events
    in a single request, which is useful for batch reporting.
    """
    created_events = []
    for event_data in events:
        event = await ssh_event.create(db=db, obj_in=event_data)
        created_events.append(event.id)
    
    return {
        "status": "success",
        "message": f"Successfully processed {len(created_events)} events",
        "event_ids": created_events
    }


@router.post("/heartbeat")
async def agent_heartbeat(
    agent_data: Dict[str, Any] = Body(...),
):
    """
    Agent heartbeat endpoint to report health status.
    
    The agent can periodically call this endpoint to report:
    - Agent version
    - System info
    - Monitoring status
    - Last event timestamp
    """
    # Simply acknowledge the heartbeat for now
    # In a production system, we would store this info and use it for monitoring
    return {
        "status": "acknowledged",
        "server_time": datetime.utcnow().isoformat()
    }