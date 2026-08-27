from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, IPvAnyAddress


class EscalationMethod(str, Enum):
    """Methods for privilege escalation."""
    SUDO = "sudo"
    SU = "su"
    SETUID = "setuid"
    PKEXEC = "pkexec"
    DOAS = "doas"
    OTHER = "other"


class PrivilegeEscalationBase(BaseModel):
    """Base model with common fields for privilege escalation events."""
    username: str = Field(..., description="User who attempted escalation")
    target_user: str = Field(..., description="Target user (usually root)")
    method: EscalationMethod = Field(..., description="Method used for escalation")
    command: Optional[str] = Field(None, description="Command executed with elevated privileges")
    success: bool = Field(..., description="Whether escalation succeeded")
    timestamp: datetime = Field(..., description="When the escalation was attempted")
    source_ip: Optional[IPvAnyAddress] = Field(None, description="Source IP if available")
    process_id: Optional[int] = Field(None, description="Process ID of the escalation attempt")
    event_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class PrivilegeEscalationCreate(PrivilegeEscalationBase):
    """Schema for creating a new privilege escalation event."""
    pass


class PrivilegeEscalationUpdate(BaseModel):
    """Schema for updating a privilege escalation event."""
    username: Optional[str] = None
    target_user: Optional[str] = None
    method: Optional[EscalationMethod] = None
    command: Optional[str] = None
    success: Optional[bool] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[IPvAnyAddress] = None
    process_id: Optional[int] = None
    event_metadata: Optional[Dict[str, Any]] = None


class PrivilegeEscalationInDB(PrivilegeEscalationBase):
    """Schema for a privilege escalation event as stored in the database."""
    id: int = Field(..., description="Unique event identifier")
    created_at: datetime = Field(..., description="When this record was created")
    updated_at: Optional[datetime] = Field(None, description="When this record was last updated")
    
    class Config:
        orm_mode = True


class PrivilegeEscalation(PrivilegeEscalationInDB):
    """Schema for a privilege escalation event returned by the API."""
    pass


class PrivilegeEscalationSearch(BaseModel):
    """Schema for searching privilege escalation events."""
    username: Optional[str] = None
    target_user: Optional[str] = None
    method: Optional[EscalationMethod] = None
    success: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Result offset for pagination")