from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Index, ARRAY
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class BruteForceAttempt(Base):
    """SQLAlchemy model for brute force attack attempts."""
    
    __tablename__ = "brute_force_attempts"
    
    # Attack information
    source_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
        index=True,
        comment="Source IP of the attack"
    )
    target_username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Username targeted in the attack"
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Number of failed attempts"
    )
    
    # Timing information
    first_attempt: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timestamp of first attempt"
    )
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timestamp of most recent attempt"
    )
    
    # Mitigation information
    blocked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        index=True,
        comment="Whether the IP was blocked"
    )
    block_duration: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Block duration in seconds"
    )
    
    # Attack details
    failed_passwords: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="List of attempted passwords if captured"
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
        # Index for IP-based queries
        Index('ix_brute_force_attempts_source_ip_last_attempt', 'source_ip', 'last_attempt'),
        
        # Index for targeted user queries
        Index('ix_brute_force_attempts_target_username_last_attempt', 'target_username', 'last_attempt'),
        
        # Index for blocked status queries
        Index('ix_brute_force_attempts_blocked_last_attempt', 'blocked', 'last_attempt'),
    )
    
    def __repr__(self) -> str:
        return (
            f"BruteForceAttempt(id={self.id!r}, source_ip={self.source_ip!r}, "
            f"target_username={self.target_username!r}, attempt_count={self.attempt_count!r}, "
            f"blocked={self.blocked!r})"
        )