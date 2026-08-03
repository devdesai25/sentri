from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseParser(ABC):
    """Base class for all log parsers"""
    
    @abstractmethod
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line into a structured event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            A structured event dict if the parsing succeeded, None otherwise.
        """
        pass