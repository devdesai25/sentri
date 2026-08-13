from datetime import datetime
from typing import List, Optional, Dict, Any, Union

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.db.crud.base import CRUDBase
from app.models.event import SSHEvent
from app.schemas.event import SSHEventCreate, SSHEventUpdate, SSHEventSearch, EventType, AuthMethod


class CRUDSSHEvent(CRUDBase[SSHEvent, SSHEventCreate, SSHEventUpdate]):
    """CRUD operations for SSH events."""
    
    async def search(
        self, db: AsyncSession, *, search_params: SSHEventSearch
    ) -> List[SSHEvent]:
        """
        Search SSH events with filtering options.
        """
        query = select(self.model)
        
        # Apply filters based on search parameters
        filters = []
        
        if search_params.username:
            filters.append(self.model.username == search_params.username)
            
        if search_params.source_ip:
            filters.append(self.model.source_ip == search_params.source_ip)
            
        if search_params.event_type:
            # Handle list of event types
            if len(search_params.event_type) == 1:
                filters.append(self.model.event_type == search_params.event_type[0])
            else:
                filters.append(self.model.event_type.in_(search_params.event_type))
            
        if search_params.auth_method:
            # Handle list of auth methods
            if len(search_params.auth_method) == 1:
                filters.append(self.model.auth_method == search_params.auth_method[0])
            else:
                filters.append(self.model.auth_method.in_(search_params.auth_method))
            
        if search_params.success is not None:
            filters.append(self.model.success == search_params.success)
            
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
        Get statistics about SSH events.
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
        
        # Success vs failure counts
        success_query = select(func.count()).select_from(self.model).where(
            and_(self.model.success == True, *time_filter) if time_filter else self.model.success == True
        )
        success_result = await db.execute(success_query)
        success_count = success_result.scalar_one()
        
        failure_query = select(func.count()).select_from(self.model).where(
            and_(self.model.success == False, *time_filter) if time_filter else self.model.success == False
        )
        failure_result = await db.execute(failure_query)
        failure_count = failure_result.scalar_one()
        
        # Events by user (top 10)
        user_query = select(
            self.model.username,
            func.count().label('count')
        ).group_by(self.model.username).order_by(text('count DESC')).limit(10)
        if time_filter:
            user_query = user_query.where(and_(*time_filter))
        user_result = await db.execute(user_query)
        events_by_user = {row[0]: row[1] for row in user_result}
        
        # Events by IP (top 10)
        ip_query = select(
            self.model.source_ip,
            func.count().label('count')
        ).where(self.model.source_ip != None).group_by(self.model.source_ip).order_by(text('count DESC')).limit(10)
        if time_filter:
            ip_query = ip_query.where(and_(*time_filter))
        ip_result = await db.execute(ip_query)
        events_by_ip = {str(row[0]): row[1] for row in ip_result if row[0]}
        
        # Events by auth method
        auth_query = select(
            self.model.auth_method,
            func.count().label('count')
        ).where(self.model.auth_method != None).group_by(self.model.auth_method)
        if time_filter:
            auth_query = auth_query.where(and_(*time_filter))
        auth_result = await db.execute(auth_query)
        events_by_auth_method = {row[0].value if row[0] else "unknown": row[1] for row in auth_result}
        
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
            "success_count": success_count,
            "failure_count": failure_count,
            "events_by_user": events_by_user,
            "events_by_ip": events_by_ip,
            "events_by_auth_method": events_by_auth_method,
            "events_by_hour": events_by_hour,
        }


# Create a singleton instance
ssh_event = CRUDSSHEvent(SSHEvent)