from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, IPvAnyAddress, validator


class AuthMethod(str, Enum):
    """Authentication methods for SSH logins."""
    PASSWORD = "password"
    PUBLICKEY = "publickey"
    KEYBOARD_INTERACTIVE = "keyboard-interactive"
    GSSAPI = "gssapi-with-mic"
    HOSTBASED = "hostbased"
    NONE = "none"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    """Types of SSH events we track."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    AUTHENTICATION_ATTEMPT = "authentication_attempt"


class SSHEventBase(BaseModel):
    """Base model with common fields for SSH events."""
    event_type: EventType
    timestamp: datetime = Field(..., description="When the event occurred")
    username: str = Field(..., description="Username associated with the event")
    source_ip: Optional[IPvAnyAddress] = Field(None, description="Source IP address")
    source_host: Optional[str] = Field(None, description="Source hostname if available")
    auth_method: Optional[AuthMethod] = Field(None, description="Authentication method used")
    success: bool = Field(..., description="Whether the authentication was successful")
    
    # Metadata fields
    session_id: Optional[str] = Field(None, description="SSH session identifier")
    process_id: Optional[int] = Field(None, description="Process ID associated with the session")
    
    # Additional context
    raw_log: Optional[str] = Field(None, description="Original log entry that generated this event")
    event_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, value):
        """Handle multiple timestamp formats."""
        if isinstance(value, datetime):
            return value
        # Handle string timestamp formats
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            # Try parsing with different formats if needed
            try:
                # Add fallback timestamp parsing if needed
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                raise ValueError(f"Invalid timestamp format: {value}")


class SSHEventCreate(SSHEventBase):
    """Schema for creating a new SSH event."""
    # Add any create-specific validation here
    pass


class SSHEventUpdate(BaseModel):
    """Schema for updating an SSH event."""
    event_type: Optional[EventType] = None
    timestamp: Optional[datetime] = None
    username: Optional[str] = None
    source_ip: Optional[IPvAnyAddress] = None
    source_host: Optional[str] = None
    auth_method: Optional[AuthMethod] = None
    success: Optional[bool] = None
    session_id: Optional[str] = None
    process_id: Optional[int] = None
    raw_log: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None


class SSHEventInDB(SSHEventBase):
    """Schema for an SSH event as stored in the database."""
    id: int = Field(..., description="Unique event identifier")
    created_at: datetime = Field(..., description="When this record was created")
    updated_at: Optional[datetime] = Field(None, description="When this record was last updated")
    
    class Config:
        orm_mode = True


class SSHEvent(SSHEventInDB):
    """Schema for an SSH event returned by the API."""
    # Add API-specific fields here
    pass


class SSHEventSearch(BaseModel):
    """Schema for searching SSH events."""
    username: Optional[str] = None
    source_ip: Optional[str] = None
    event_type: Optional[List[EventType]] = None
    auth_method: Optional[List[AuthMethod]] = None
    success: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Result offset for pagination")


class SSHEventStatistics(BaseModel):
    """Schema for SSH event statistics."""
    total_events: int
    success_count: int
    failure_count: int
    events_by_user: Dict[str, int]
    events_by_ip: Dict[str, int]
    events_by_auth_method: Dict[str, int]
    events_by_hour: Dict[int, int]