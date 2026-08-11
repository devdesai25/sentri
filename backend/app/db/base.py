from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Column, Integer, DateTime, func
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all models."""
    
    @declared_attr.directive
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
    
    # Common columns for all models
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, 
                                             server_default=func.now(),
                                             nullable=False)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, 
                                                      onupdate=func.now(),
                                                      nullable=True)