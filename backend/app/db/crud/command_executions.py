from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.db.crud.base import CRUDBase
from app.models.command_execution import CommandExecution
from app.schemas.command_execution import CommandExecutionCreate, CommandExecutionUpdate, CommandExecutionSearch


class CRUDCommandExecution(CRUDBase[CommandExecution, CommandExecutionCreate, CommandExecutionUpdate]):
    """CRUD operations for command execution events."""
    
    async def search(
        self, db: AsyncSession, *, search_params: CommandExecutionSearch
    ) -> List[CommandExecution]:
        """
        Search command execution events with filtering options.
        """
        query = select(self.model)
        
        # Apply filters based on search parameters
        filters = []
        
        if search_params.username:
            filters.append(self.model.username == search_params.username)
            
        if search_params.host:
            filters.append(self.model.host == search_params.host)
            
        if search_params.command:
            # Use ILIKE for partial command matching
            filters.append(self.model.command.ilike(f"%{search_params.command}%"))
            
        if search_params.risk_level:
            filters.append(self.model.risk_level == search_params.risk_level)
            
        if search_params.start_time:
            filters.append(self.model.timestamp >= search_params.start_time)
            
        if search_params.end_time:
            filters.append(self.model.timestamp <= search_params.end_time)
            
        if filters:
            query = query.where(and_(*filters))
            
        # Apply pagination
        query = query.order_by(self.model.timestamp.desc())
        query = query.offset(search_params.offset).limit(search_params.limit)
        
        # Execute query
        result = await db.execute(query)
        return result.scalars().all()
    
    async def get_stats(
        self, db: AsyncSession, *, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get statistics about command execution events.
        """
        # Base time filter
        time_filter = []
        if start_time:
            time_filter.append(self.model.timestamp >= start_time)
        if end_time:
            time_filter.append(self.model.timestamp <= end_time)
        
        # Total events
        total_query = select(func.count()).select_from(self.model)
        if time_filter:
            total_query = total_query.where(and_(*time_filter))
        total_result = await db.execute(total_query)
        total_events = total_result.scalar_one()
        
        # Events by risk level
        risk_query = select(
            self.model.risk_level,
            func.count().label('count')
        ).group_by(self.model.risk_level)
        if time_filter:
            risk_query = risk_query.where(and_(*time_filter))
        risk_result = await db.execute(risk_query)
        events_by_risk = {row[0] or "unknown": row[1] for row in risk_result}
        
        # Events by user (top 10)
        user_query = select(
            self.model.username,
            func.count().label('count')
        ).group_by(self.model.username).order_by(text('count DESC')).limit(10)
        if time_filter:
            user_query = user_query.where(and_(*time_filter))
        user_result = await db.execute(user_query)
        events_by_user = {row[0]: row[1] for row in user_result}
        
        # Events by host (top 10)
        host_query = select(
            self.model.host,
            func.count().label('count')
        ).group_by(self.model.host).order_by(text('count DESC')).limit(10)
        if time_filter:
            host_query = host_query.where(and_(*time_filter))
        host_result = await db.execute(host_query)
        events_by_host = {row[0]: row[1] for row in host_result}
        
        # Events by hour of day
        hour_query = select(
            func.extract('hour', self.model.timestamp).label('hour'),
            func.count().label('count')
        ).group_by(text('hour')).order_by(text('hour'))
        if time_filter:
            hour_query = hour_query.where(and_(*time_filter))
        hour_result = await db.execute(hour_query)
        events_by_hour = {int(row[0]): row[1] for row in hour_result}
        
        return {
            "total_events": total_events,
            "events_by_risk": events_by_risk,
            "events_by_user": events_by_user,
            "events_by_host": events_by_host,
            "events_by_hour": events_by_hour,
        }


# Create a singleton instance
command_execution = CRUDCommandExecution(CommandExecution)