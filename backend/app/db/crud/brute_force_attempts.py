from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.db.crud.base import CRUDBase
from app.models.brute_force_attempt import BruteForceAttempt
from app.schemas.brute_force import BruteForceAttemptCreate, BruteForceAttemptUpdate, BruteForceAttemptSearch


class CRUDBruteForceAttempt(CRUDBase[BruteForceAttempt, BruteForceAttemptCreate, BruteForceAttemptUpdate]):
    """CRUD operations for brute force attempt events."""
    
    async def search(
        self, db: AsyncSession, *, search_params: BruteForceAttemptSearch
    ) -> List[BruteForceAttempt]:
        """
        Search brute force attempt events with filtering options.
        """
        query = select(self.model)
        
        # Apply filters based on search parameters
        filters = []
        
        if search_params.source_ip:
            filters.append(self.model.source_ip == search_params.source_ip)
            
        if search_params.target_username:
            filters.append(self.model.target_username == search_params.target_username)
            
        if search_params.blocked is not None:
            filters.append(self.model.blocked == search_params.blocked)
            
        if search_params.start_time:
            filters.append(self.model.last_attempt >= search_params.start_time)
            
        if search_params.end_time:
            filters.append(self.model.last_attempt <= search_params.end_time)
            
        if filters:
            query = query.where(and_(*filters))
            
        # Apply pagination
        query = query.order_by(self.model.last_attempt.desc())
        query = query.offset(search_params.offset).limit(search_params.limit)
        
        # Execute query
        result = await db.execute(query)
        return result.scalars().all()
    
    async def get_stats(
        self, db: AsyncSession, *, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get statistics about brute force attempt events.
        """
        # Base time filter
        time_filter = []
        if start_time:
            time_filter.append(self.model.last_attempt >= start_time)
        if end_time:
            time_filter.append(self.model.last_attempt <= end_time)
        
        # Total events
        total_query = select(func.count()).select_from(self.model)
        if time_filter:
            total_query = total_query.where(and_(*time_filter))
        total_result = await db.execute(total_query)
        total_events = total_result.scalar_one()
        
        # Blocked vs unblocked counts
        blocked_query = select(func.count()).select_from(self.model).where(
            and_(self.model.blocked == True, *time_filter) if time_filter else self.model.blocked == True
        )
        blocked_result = await db.execute(blocked_query)
        blocked_count = blocked_result.scalar_one()
        
        unblocked_query = select(func.count()).select_from(self.model).where(
            and_(self.model.blocked == False, *time_filter) if time_filter else self.model.blocked == False
        )
        unblocked_result = await db.execute(unblocked_query)
        unblocked_count = unblocked_result.scalar_one()
        
        # Top source IPs (top 10)
        ip_query = select(
            self.model.source_ip,
            func.count().label('count')
        ).group_by(self.model.source_ip).order_by(text('count DESC')).limit(10)
        if time_filter:
            ip_query = ip_query.where(and_(*time_filter))
        ip_result = await db.execute(ip_query)
        events_by_ip = {str(row[0]): row[1] for row in ip_result}
        
        # Top targeted usernames (top 10)
        username_query = select(
            self.model.target_username,
            func.count().label('count')
        ).group_by(self.model.target_username).order_by(text('count DESC')).limit(10)
        if time_filter:
            username_query = username_query.where(and_(*time_filter))
        username_result = await db.execute(username_query)
        events_by_username = {row[0]: row[1] for row in username_result}
        
        # Average attempts per attack
        avg_query = select(func.avg(self.model.attempt_count)).select_from(self.model)
        if time_filter:
            avg_query = avg_query.where(and_(*time_filter))
        avg_result = await db.execute(avg_query)
        avg_attempts = avg_result.scalar_one() or 0
        
        return {
            "total_events": total_events,
            "blocked_count": blocked_count,
            "unblocked_count": unblocked_count,
            "events_by_ip": events_by_ip,
            "events_by_username": events_by_username,
            "average_attempts": float(avg_attempts),
        }


# Create a singleton instance
brute_force_attempt = CRUDBruteForceAttempt(BruteForceAttempt)