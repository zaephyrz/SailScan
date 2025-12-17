from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, Float
from sqlalchemy.sql import func
from . import Base

class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(String(20), primary_key=True, index=True)  # CVE-YYYY-NNNNN
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_severity = Column(String(20), nullable=True)
    published_date = Column(DateTime(timezone=True))
    last_modified = Column(DateTime(timezone=True))
    references = Column(JSON, nullable=True)
    affected_products = Column(JSON, nullable=True)
    exploit_available = Column(String(10), nullable=True)
    patch_available = Column(String(10), nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())