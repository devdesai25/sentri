from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class RiskLevel(str, Enum):
    """Risk levels for command execution."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

    @property
    def numeric_value(self) -> int:
        """Get numeric value of risk level (0-4)."""
        mapping = {
            self.MINIMAL: 0,
            self.LOW: 1,
            self.MEDIUM: 2,
            self.HIGH: 3,
            self.CRITICAL: 4
        }
        return mapping[self]


class CommandBase(BaseModel):
    """Base model with common fields for command events."""
    command: str = Field(..., description="The command that was executed")
    arguments: str = Field("", description="Arguments passed to the command")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the command was executed")
    username: str = Field(..., description="User who executed the command")
    working_directory: Optional[str] = Field(None, description="Directory where the command was executed")
    
    # Additional context
    source_ip: Optional[str] = Field(None, description="Source IP if available")
    process_id: Optional[int] = Field(None, description="Process ID of the command")
    command_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class CommandRiskRequest(CommandBase):
    """Request schema for command risk assessment."""
    pass


class CommandRiskResponse(BaseModel):
    """Response schema for command risk assessment."""
    risk_level: RiskLevel = Field(..., description="Assessed risk level of the command")
    reason: str = Field(..., description="Explanation for the risk assessment")

class ExplanationSection(BaseModel):
    """A section of the command explanation."""
    title: str = Field(..., description="Title of the explanation section")
    content: str = Field(..., description="Content of the explanation section")


class CommandExplainRequest(CommandBase):
    """Request schema for command explanation."""
    context: Optional[str] = Field(None, description="Optional context about execution environment")


class CommandExplainResponse(BaseModel):
    """Response schema for command explanation."""
    command: str = Field(..., description="Command that was explained")
    summary: str = Field(..., description="Brief summary of what the command does")
    sections: list[ExplanationSection] = Field(..., description="Detailed explanation sections")
    risk_level: RiskLevel = Field(..., description="Risk level assessment")
    risk_explanation: Optional[str] = Field(None, description="Explanation of identified risks")