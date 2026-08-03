from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseStorage(ABC):
    """Base class for all storage backends"""
    
    @abstractmethod
    def store_event(self, event: Dict[str, Any]) -> None:
        """
        Store an event in the storage backend.
        
        Args:
            event: The event to store
        """
        pass
        
    @abstractmethod
    def query_events(self, 
                     event_type: Optional[str] = None,
                     user: Optional[str] = None, 
                     ip_address: Optional[str] = None,
                     start_time: Optional[str] = None,
                     end_time: Optional[str] = None,
                     limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Query events from storage based on search criteria.
        
        Args:
            event_type: Filter by event type (e.g., ssh_login_success)
            user: Filter by username
            ip_address: Filter by IP address
            start_time: Filter events after this time (ISO format)
            end_time: Filter events before this time (ISO format)
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        pass
        
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about stored events.
        
        Returns:
            Dict containing event statistics
        """
        pass
        
    @abstractmethod
    def cleanup_old_events(self, max_age_days: int = 30) -> int:
        """
        Delete events older than the specified age.
        
        Args:
            max_age_days: Maximum age of events in days
            
        Returns:
            Number of events deleted
        """
        pass