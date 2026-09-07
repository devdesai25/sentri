from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, IPvAnyAddress


class RiskLevel(str, Enum):
    """Risk levels for command execution."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class CommandExecutionBase(BaseModel):
    """Base model with common fields for command execution events."""
    command: str = Field(..., description="Command that was executed")
    timestamp: datetime = Field(..., description="When the command was executed")
    username: str = Field(..., description="User who executed the command")
    host: str = Field(..., description="Host where command was executed")
    exit_code: Optional[int] = Field(None, description="Command exit code")
    duration: Optional[float] = Field(None, description="Execution time in seconds")
    risk_level: Optional[str] = Field(None, description="Assessed risk level")
    source_ip: Optional[IPvAnyAddress] = Field(None, description="Source IP address")
    working_directory: Optional[str] = Field(None, description="Working directory")
    process_id: Optional[int] = Field(None, description="Process ID of command")
    event_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class CommandExecutionCreate(CommandExecutionBase):
    """Schema for creating a new command execution event."""
    pass


class CommandExecutionUpdate(BaseModel):
    """Schema for updating a command execution event."""
    command: Optional[str] = None
    timestamp: Optional[datetime] = None
    username: Optional[str] = None
    host: Optional[str] = None
    exit_code: Optional[int] = None
    duration: Optional[float] = None
    risk_level: Optional[str] = None
    source_ip: Optional[IPvAnyAddress] = None
    working_directory: Optional[str] = None
    process_id: Optional[int] = None
    event_metadata: Optional[Dict[str, Any]] = None


class CommandExecutionInDB(CommandExecutionBase):
    """Schema for a command execution event as stored in the database."""
    id: int = Field(..., description="Unique event identifier")
    created_at: datetime = Field(..., description="When this record was created")
    updated_at: Optional[datetime] = Field(None, description="When this record was last updated")
    
    class Config:
        orm_mode = True


class CommandExecution(CommandExecutionInDB):
    """Schema for a command execution event returned by the API."""
    pass


class CommandExecutionSearch(BaseModel):
    """Schema for searching command execution events."""
    username: Optional[str] = None
    host: Optional[str] = None
    command: Optional[str] = None
    risk_level: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Result offset for pagination")