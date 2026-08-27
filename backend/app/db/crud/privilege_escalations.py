from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.db.crud.base import CRUDBase
from app.models.privilege_escalation import PrivilegeEscalation
from app.schemas.privilege_escalation import PrivilegeEscalationCreate, PrivilegeEscalationUpdate, PrivilegeEscalationSearch, EscalationMethod


class CRUDPrivilegeEscalation(CRUDBase[PrivilegeEscalation, PrivilegeEscalationCreate, PrivilegeEscalationUpdate]):
    """CRUD operations for privilege escalation events."""
    
    async def search(
        self, db: AsyncSession, *, search_params: PrivilegeEscalationSearch
    ) -> List[PrivilegeEscalation]:
        """
        Search privilege escalation events with filtering options.
        """
        query = select(self.model)
        
        # Apply filters based on search parameters
        filters = []
        
        if search_params.username:
            filters.append(self.model.username == search_params.username)
            
        if search_params.target_user:
            filters.append(self.model.target_user == search_params.target_user)
            
        if search_params.method:
            filters.append(self.model.method == search_params.method)
            
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
        Get statistics about privilege escalation events.
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
        
        # Events by escalation method
        method_query = select(
            self.model.method,
            func.count().label('count')
        ).group_by(self.model.method)
        if time_filter:
            method_query = method_query.where(and_(*time_filter))
        method_result = await db.execute(method_query)
        events_by_method = {row[0].value: row[1] for row in method_result}
        
        # Events by user (top 10)
        user_query = select(
            self.model.username,
            func.count().label('count')
        ).group_by(self.model.username).order_by(text('count DESC')).limit(10)
        if time_filter:
            user_query = user_query.where(and_(*time_filter))
        user_result = await db.execute(user_query)
        events_by_user = {row[0]: row[1] for row in user_result}
        
        # Events by target user (top 10)
        target_query = select(
            self.model.target_user,
            func.count().label('count')
        ).group_by(self.model.target_user).order_by(text('count DESC')).limit(10)
        if time_filter:
            target_query = target_query.where(and_(*time_filter))
        target_result = await db.execute(target_query)
        events_by_target = {row[0]: row[1] for row in target_result}
        
        return {
            "total_events": total_events,
            "success_count": success_count,
            "failure_count": failure_count,
            "events_by_method": events_by_method,
            "events_by_user": events_by_user,
            "events_by_target": events_by_target,
        }


# Create a singleton instance
privilege_escalation = CRUDPrivilegeEscalation(PrivilegeEscalation)