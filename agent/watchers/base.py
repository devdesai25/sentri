from abc import ABC, abstractmethod
from typing import Callable, Dict, Any, Optional

class BaseWatcher(ABC):
    """Base class for all log watchers"""
    
    def __init__(self, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Initialize a watcher with a callback to be called for each new log entry.
        
        Args:
            callback: Function to call with (log_line, metadata) for each new log entry
        """
        self.callback = callback
        self._running = False
        
    @abstractmethod
    async def start(self) -> None:
        """Start watching for new log entries"""
        pass
        
    @abstractmethod
    async def stop(self) -> None:
        """Stop watching for new log entries"""
        pass
    
    @property
    def is_running(self) -> bool:
        """Return whether the watcher is currently running"""
        return self._running