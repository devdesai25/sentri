from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, Index, Enum
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.schemas.privilege_escalation import EscalationMethod


class PrivilegeEscalation(Base):
    """SQLAlchemy model for privilege escalation events."""
    
    __tablename__ = "privilege_escalations"
    
    # User information
    username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="User who attempted escalation"
    )
    target_user: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Target user (usually root)"
    )
    
    # Escalation details
    method: Mapped[EscalationMethod] = mapped_column(
        Enum(EscalationMethod),
        nullable=False,
        index=True,
        comment="Method used for escalation"
    )
    command: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Command executed with elevated privileges"
    )
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        index=True,
        comment="Whether escalation succeeded"
    )
    
    # Event timing
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When the escalation was attempted"
    )
    
    # Additional context
    source_ip: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        index=True,
        comment="Source IP if available"
    )
    process_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Process ID of the escalation attempt"
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
        Index('ix_privilege_escalations_username_timestamp', 'username', 'timestamp'),
        
        # Index for success/failure analysis
        Index('ix_privilege_escalations_method_success', 'method', 'success'),
        
        # Index for target user analysis
        Index('ix_privilege_escalations_target_user_timestamp', 'target_user', 'timestamp'),
    )
    
    def __repr__(self) -> str:
        return (
            f"PrivilegeEscalation(id={self.id!r}, username={self.username!r}, "
            f"target_user={self.target_user!r}, method={self.method!r}, "
            f"success={self.success!r}, timestamp={self.timestamp!r})"
        )