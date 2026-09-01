from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, IPvAnyAddress


class BruteForceAttemptBase(BaseModel):
    """Base model with common fields for brute force attempt events."""
    source_ip: IPvAnyAddress = Field(..., description="Source IP of the attack")
    target_username: str = Field(..., description="Username targeted in the attack")
    attempt_count: int = Field(..., description="Number of failed attempts")
    first_attempt: datetime = Field(..., description="Timestamp of first attempt")
    last_attempt: datetime = Field(..., description="Timestamp of most recent attempt")
    blocked: bool = Field(..., description="Whether the IP was blocked")
    block_duration: Optional[int] = Field(None, description="Block duration in seconds")
    failed_passwords: Optional[List[str]] = Field(None, description="List of attempted passwords if captured")
    event_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class BruteForceAttemptCreate(BruteForceAttemptBase):
    """Schema for creating a new brute force attempt event."""
    pass


class BruteForceAttemptUpdate(BaseModel):
    """Schema for updating a brute force attempt event."""
    source_ip: Optional[IPvAnyAddress] = None
    target_username: Optional[str] = None
    attempt_count: Optional[int] = None
    first_attempt: Optional[datetime] = None
    last_attempt: Optional[datetime] = None
    blocked: Optional[bool] = None
    block_duration: Optional[int] = None
    failed_passwords: Optional[List[str]] = None
    event_metadata: Optional[Dict[str, Any]] = None


class BruteForceAttemptInDB(BruteForceAttemptBase):
    """Schema for a brute force attempt event as stored in the database."""
    id: int = Field(..., description="Unique event identifier")
    created_at: datetime = Field(..., description="When this record was created")
    updated_at: Optional[datetime] = Field(None, description="When this record was last updated")
    
    class Config:
        orm_mode = True


class BruteForceAttempt(BruteForceAttemptInDB):
    """Schema for a brute force attempt event returned by the API."""
    pass


class BruteForceAttemptSearch(BaseModel):
    """Schema for searching brute force attempt events."""
    source_ip: Optional[str] = None
    target_username: Optional[str] = None
    blocked: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Result offset for pagination")