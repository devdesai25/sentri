from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, ForeignKey, Index, Enum
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.schemas.event import AuthMethod, EventType


class SSHEvent(Base):
    """SQLAlchemy model for SSH login events."""
    
    __tablename__ = "ssh_events"
    
    # Core event information
    event_type: Mapped[EventType] = mapped_column(
        Enum(EventType), 
        nullable=False, 
        # index=True,
        comment="Type of SSH event"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False, 
        index=True,
        comment="When the event occurred"
    )
    
    # User information
    username: Mapped[str] = mapped_column(
        String(100), 
        nullable=False, 
        index=True,
        comment="Username associated with the event"
    )
    
    # Source information
    source_ip: Mapped[Optional[str]] = mapped_column(
        INET, 
        nullable=True,
        index=True,
        comment="Source IP address"
    )
    source_host: Mapped[Optional[str]] = mapped_column(
        String(255), 
        nullable=True,
        index=True,
        comment="Source hostname if available"
    )
    
    # Authentication information
    auth_method: Mapped[Optional[AuthMethod]] = mapped_column(
        Enum(AuthMethod),
        nullable=True,
        index=True,
        comment="Authentication method used"
    )
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        index=True,
        comment="Whether the authentication was successful"
    )
    
    # Session information
    session_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        # index=True,
        comment="SSH session identifier"
    )
    process_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Process ID associated with the session"
    )
    
    # Log details
    raw_log: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Original log entry that generated this event"
    )
    
    # Additional metadata stored as JSON
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        default={},
        comment="Additional metadata as JSON"
    )
    
    # Create composite indices for common query patterns
    __table_args__ = (
        # Index for time-based user activity queries
        Index('ix_ssh_events_username_timestamp', 'username', 'timestamp'),
        
        # Index for IP-based activity queries
        Index('ix_ssh_events_source_ip_timestamp', 'source_ip', 'timestamp'),
        
        # Index for auth method analysis
        Index('ix_ssh_events_auth_method_success', 'auth_method', 'success'),
        
        # Index for session tracking
        Index('ix_ssh_events_session_id', 'session_id'),
    )
    
    def __repr__(self) -> str:
        return (
            f"SSHEvent(id={self.id!r}, username={self.username!r}, "
            f"source_ip={self.source_ip!r}, timestamp={self.timestamp!r}, "
            f"event_type={self.event_type!r}, success={self.success!r})"
        )