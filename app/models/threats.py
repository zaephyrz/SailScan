from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from . import Base

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    description = Column(Text, nullable=False)
    detection = Column(String(255), nullable=True)
    location = Column(String(500), nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="threats")