from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, Float, Index, Enum
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CommandExecution(Base):
    """SQLAlchemy model for command execution events."""
    
    __tablename__ = "command_executions"
    
    # Command information
    command: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Command that was executed"
    )
    
    # Execution context
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When the command was executed"
    )
    username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="User who executed the command"
    )
    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Host where command was executed"
    )
    exit_code: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Command exit code"
    )
    duration: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Execution time in seconds"
    )
    risk_level: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        comment="Assessed risk level"
    )
    
    # Additional context
    source_ip: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        index=True,
        comment="Source IP address"
    )
    working_directory: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Working directory"
    )
    process_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Process ID of command"
    )
    
    # Metadata
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        default={},
        comment="Additional metadata as JSON"
    )
    
    # Indexes for common query patterns
    __table_args__ = (
        # Index for user activity over time
        Index('ix_command_executions_username_timestamp', 'username', 'timestamp'),
        
        # Index for risk level filtering
        # Index('ix_command_executions_risk_level', 'risk_level'),
        
        # Index for IP-based activity
        Index('ix_command_executions_source_ip_timestamp', 'source_ip', 'timestamp'),
    )
    
    def __repr__(self) -> str:
        return (
            f"CommandExecution(id={self.id!r}, username={self.username!r}, "
            f"command={self.command!r}, timestamp={self.timestamp!r})"
        )