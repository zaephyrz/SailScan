from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer)
    threat_type = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
